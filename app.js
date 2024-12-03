require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
//adarsh
const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

pool.getConnection((err, connection) => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to MySQL database');

    connection.query(`CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        email VARCHAR(255) UNIQUE,
        phone_number VARCHAR(20),
        user_type ENUM('seller', 'buyer'),
        password VARCHAR(255)
    )`, (error) => {
        if (error) {
            console.error('Error creating users table:', error);
            return;
        }
        console.log('Users table created successfully');
    });

    connection.query(`CREATE TABLE IF NOT EXISTS properties (
        id INT AUTO_INCREMENT PRIMARY KEY,
        seller_id INT,
        place VARCHAR(255),
        area FLOAT,
        num_bedrooms INT,
        num_bathrooms INT,
        hospitals_nearby TINYINT(1),
        colleges_nearby TINYINT(1),
        image_url VARCHAR(255),
        FOREIGN KEY (seller_id) REFERENCES users(id)
    )`, (error) => {
        if (error) {
            console.error('Error creating properties table:', error);
            return;
        }
        console.log('Properties table created successfully');
    });

    connection.query(`CREATE TABLE IF NOT EXISTS interests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        buyer_id INT,
        property_id INT,
        FOREIGN KEY (buyer_id) REFERENCES users(id),
        FOREIGN KEY (property_id) REFERENCES properties(id)
    )`, (error) => {
        if (error) {
            console.error('Error creating interests table:', error);
            return;
        }
        console.log('Interests table created successfully');
    });

    connection.release();
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}


const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage, limits: { fileSize: 10 * 1024 * 1024 } }); 

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    logger: true,
    debug: true
});

transporter.verify((error, success) => {
    if (error) {
        console.error('Error verifying transporter:', error);
    } else {
        console.log('Transporter is ready to send messages');
    }
});

app.post('/register', async (req, res) => {
    const { first_name, last_name, email, phone_number, user_type, password } = req.body;
    if (password.length < 8) {
        return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        pool.query('INSERT INTO users (first_name, last_name, email, phone_number, user_type, password) VALUES (?, ?, ?, ?, ?, ?)', 
            [first_name, last_name, email, phone_number, user_type, hashedPassword],
            (error, results) => {
                if (error) {
                    if (error.code === 'ER_DUP_ENTRY') {
                        res.status(400).json({ message: 'Email already exists' });
                    } else {
                        res.status(500).json({ message: 'Internal server error' });
                    }
                } else {
                    res.status(201).json({ message: 'User registered successfully' });
                }
            }
        );
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
});


app.post('/login', (req, res) => {
    const { email, password } = req.body;
    pool.query('SELECT * FROM users WHERE email = ?', [email], async (error, results) => {
        if (error) {
            return res.sendStatus(500);
        }
        if (results.length > 0) {
            const user = results[0];
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                const token = jwt.sign({ id: user.id, email: user.email, user_type: user.user_type }, process.env.JWT_SECRET, { expiresIn: '1h' });
                return res.status(200).json({ token, userType: user.user_type });
            } else {
                return res.sendStatus(401); 
            }
        } else {
            return res.sendStatus(404); 
        }
    });
});

app.get('/seller/:id', authenticateToken, (req, res) => {
    const sellerId = req.params.id;

    pool.query('SELECT id, first_name, last_name, email, phone_number FROM users WHERE id = ?', [sellerId], (error, results) => {
        if (error) {
            console.error('Error fetching seller details from database:', error);
            return res.status(500).json({ message: 'Internal server error' });
        }
        if (results.length > 0) {
            res.status(200).json(results[0]);
        } else {
            res.status(404).json({ message: 'Seller not found' });
        }
    });
});

app.post('/properties', authenticateToken, upload.single('image'), (req, res) => {
    const seller_id = req.user.id;
    const { place, area, num_bedrooms, num_bathrooms, hospitals_nearby, colleges_nearby } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : null;

    pool.query('INSERT INTO properties (seller_id, place, area, num_bedrooms, num_bathrooms, hospitals_nearby, colleges_nearby, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [seller_id, place, area, num_bedrooms, num_bathrooms, hospitals_nearby === 'true' ? 1 : 0, colleges_nearby === 'true' ? 1 : 0, image_url],
        (error, results) => {
            if (error) {
                console.error('Error inserting property into database:', error);
                return res.status(500).json({ message: 'Internal server error', error });
            } else {
                return res.status(201).json({ message: 'Property posted successfully' });
            }
        }
    );
});

app.put('/properties/:id', authenticateToken, upload.single('image'), (req, res) => {
    const propertyId = req.params.id;
    const { place, area, num_bedrooms, num_bathrooms, hospitals_nearby, colleges_nearby } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : req.body.image_url;

    pool.query('UPDATE properties SET place=?, area=?, num_bedrooms=?, num_bathrooms=?, hospitals_nearby=?, colleges_nearby=?, image_url=? WHERE id=?',
        [place, area, num_bedrooms, num_bathrooms, hospitals_nearby === 'true' ? 1 : 0, colleges_nearby === 'true' ? 1 : 0, image_url, propertyId],
        (error, results) => {
            if (error) {
                console.error('Error updating property in database:', error);
                return res.status(500).json({ message: 'Internal server error', error });
            } else {
                return res.status(200).json({ message: 'Property updated successfully' });
            }
        }
    );
});

app.delete('/properties/:id', authenticateToken, (req, res) => {
    const propertyId = req.params.id;
    pool.query('DELETE FROM properties WHERE id=?', [propertyId], (error, results) => {
        if (error) {
            console.error('Error deleting property from database:', error);
            res.status(500).json({ message: 'Internal server error' });
        } else {
            res.status(200).json({ message: 'Property deleted successfully' });
        }
    });
});


app.get('/properties', (req, res) => {
    pool.query('SELECT * FROM properties', (error, results) => {
        if (error) {
            console.error('Error fetching properties from database:', error);
            res.status(500).json({ message: 'Internal server error' });
        } else {
            res.status(200).json(results);
        }
    });
});

app.post('/properties/:id/interest', authenticateToken, (req, res) => {
    const propertyId = req.params.id;
    const buyerId = req.user.id;

    pool.query('INSERT INTO interests (buyer_id, property_id) VALUES (?, ?)', [buyerId, propertyId], (error, results) => {
        if (error) {
            console.error('Error expressing interest in property:', error);
            return res.status(500).json({ message: 'Internal server error' });
        } else {
            res.status(201).json({ message: 'Interest expressed successfully' });

            pool.query('SELECT * FROM properties WHERE id = ?', [propertyId], (error, propertyResults) => {
                if (error) {
                    console.error('Error fetching property from database:', error);
                    return;
                }
                if (propertyResults.length > 0) {
                    const property = propertyResults[0];
                    pool.query('SELECT id, first_name, last_name, email, phone_number FROM users WHERE id = ?', [property.seller_id], (error, userResults) => {
                        if (error) {
                            console.error('Error fetching seller details from database:', error);
                            return;
                        }
                        if (userResults.length > 0) {
                            const seller = userResults[0];
                            const mailOptionsSeller = {
                                from: process.env.EMAIL_USER,
                                to: seller.email,
                                subject: 'Interest in Your Property',
                                html: `
                                    <p>Hi ${seller.first_name},</p>
                                    <p>Your property listing has received interest from a potential buyer.</p>
                                    <p>Property Details:</p>
                                    <ul>
                                        <li>Place: ${property.place}</li>
                                        <li>Area: ${property.area} sqft</li>
                                        <li>Bedrooms: ${property.num_bedrooms}</li>
                                        <li>Bathrooms: ${property.num_bathrooms}</li>
                                    </ul>
                                    <p>Buyer's Contact Details:</p>
                                    <ul>
                                        <li>Name: ${req.user.first_name} ${req.user.last_name}</li>
                                        <li>Email: ${req.user.email}</li>
                                        <li>Phone Number: ${req.user.phone_number}</li>
                                    </ul>
                                    <p>Feel free to reach out to the buyer for further inquiries.</p>
                                `
                            };

                            transporter.sendMail(mailOptionsSeller, (error, info) => {
                                if (error) {
                                    console.error('Error sending email to seller:', error);
                                } else {
                                    console.log('Email sent to seller:', info.response);
                                }
                            });

                            const mailOptionsBuyer = {
                                from: process.env.EMAIL_USER,
                                to: req.user.email,
                                subject: 'Property Details',
                                html: `
                                    <p>Hi,</p>
                                    <p>You recently expressed interest in a property and here are the seller's contact details:</p>
                                    <ul>
                                        <li>Name: ${seller.first_name} ${seller.last_name}</li>
                                        <li>Email: ${seller.email}</li>
                                        <li>Phone Number: ${seller.phone_number}</li>
                                    </ul>
                                    <p>Feel free to reach out to the seller for further inquiries.</p>
                                `
                            };

                            transporter.sendMail(mailOptionsBuyer, (error, info) => {
                                if (error) {
                                    console.error('Error sending email to buyer:', error);
                                } else {
                                    console.log('Email sent to buyer:', info.response);
                                }
                            });
                        } else {
                            console.error('Seller details not found');
                        }
                    });
                } else {
                    console.error('Property not found');
                }
            });
        }
    });
});

app.get('/properties/:id', authenticateToken, (req, res) => {
    const propertyId = req.params.id;
    const buyerEmail = req.user.email;

    pool.query('SELECT * FROM properties WHERE id = ?', [propertyId], (error, propertyResults) => {
        if (error) {
            console.error('Error fetching property from database:', error);
            return res.status(500).json({ message: 'Internal server error' });
        }
        if (propertyResults.length > 0) {
            const property = propertyResults[0];
            pool.query('SELECT id, first_name, last_name, email, phone_number FROM users WHERE id = ?', [property.seller_id], (error, userResults) => {
                if (error) {
                    console.error('Error fetching seller details from database:', error);
                    return res.status(500).json({ message: 'Internal server error' });
                }
                if (userResults.length > 0) {
                    const seller = userResults[0];
                    const mailOptionsSeller = {
                        from: process.env.EMAIL_USER,
                        to: seller.email,
                        subject: 'Interest in Your Property',
                        html: `
                            <p>Hi ${seller.first_name},</p>
                            <p>Your property listing has received interest from a potential buyer.</p>
                            <p>Property Details:</p>
                            <ul>
                                <li>Place: ${property.place}</li>
                                <li>Area: ${property.area} sqft</li>
                                <li>Bedrooms: ${property.num_bedrooms}</li>
                                <li>Bathrooms: ${property.num_bathrooms}</li>
                            </ul>
                            <p>Buyer's Contact Details:</p>
                            <ul>
                                <li>Name: ${req.user.first_name} ${req.user.last_name}</li>
                                <li>Email: ${req.user.email}</li>
                                <li>Phone Number: ${req.user.phone_number}</li>
                            </ul>
                            <p>Feel free to reach out to the buyer for further inquiries.</p>
                        `
                    };

                    transporter.sendMail(mailOptionsSeller, (error, info) => {
                        if (error) {
                            console.error('Error sending email to seller:', error);
                        } else {
                            console.log('Email sent to seller:', info.response);
                        }
                    });

                    const mailOptionsBuyer = {
                        from: process.env.EMAIL_USER,
                        to: buyerEmail,
                        subject: 'Property Details',
                        html: `
                            <p>Hi,</p>
                            <p>You recently viewed a property and here are the seller's contact details:</p>
                            <ul>
                                <li>Name: ${seller.first_name} ${seller.last_name}</li>
                                <li>Email: ${seller.email}</li>
                                <li>Phone Number: ${seller.phone_number}</li>
                                </ul>
                                <p>Feel free to reach out to the seller for further inquiries.</p>
                            `
                        };
    
                        transporter.sendMail(mailOptionsBuyer, (error, info) => {
                            if (error) {
                                console.error('Error sending email to buyer:', error);
                            } else {
                                console.log('Email sent to buyer:', info.response);
                            }
                        });
    
                        res.status(200).json({ message: 'Property details sent to buyer' });
                    } else {
                        console.error('Seller details not found');
                        res.status(404).json({ message: 'Seller details not found' });
                    }
                });
            } else {
                console.error('Property not found');
                res.status(404).json({ message: 'Property not found' });
            }
        });
    });
    
    app.listen(port, () => {
        console.log(`Server running on port ${port}`);
    });
