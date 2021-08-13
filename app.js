require('dotenv').config();
const express = require('express');
const db = require('./db/index');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();  
const PORT = process.env.PORT || 5000;
const saltRounds = 10;
const callbackURL = process.env.NODE_ENV === 'production' ? process.env.GOOGLE_CALLBACK_URL_PROD : GOOGLE_CALLBACK_URL_DEV

// Middlewares
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(passport.initialize());

function verifyToken(req, res, next){  // Add this as a middleware to routes which need token verification
    let bearerHeader = req.headers.authorization;
    if (typeof bearerHeader !== undefined) {
        let bearer = bearerHeader.split(' ');
        const token = bearer[1];
        req.token = token
        jwt.verify(req.token, process.env.JWT_SECRET, (err, done) => {
            if (!err) {
                res.json({
                    done
                });
                next();
            } else {
                res.json({
                    error: err
                });
            }
        });
    } else {
        res.status(403);
    }
}

passport.use(new LocalStrategy(async (username, password, done) => {
        try {
            const user = await db.query('SELECT * from users WHERE username=$1', [username]);
            if (user.rows.length==0) {
                return done(null, 'Incorrect Username or Password');
            } else {
                bcrypt.compare(password, user.rows[0].password, (err, result) => {
                    if (!err) {
                        return done(null, user.rows[0]);
                    } else {
                        return done(null, 'Incorrect Username or Password');
                    }
                });
            }
        } catch (error) {
            return done(error)
        }
}));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: callbackURL+'/auth/google/callback'
}, async (accessToken, refreshToken, profile, cb) => {
    try {
        const user = await db.query('SELECT * from users WHERE google_id=$1', [profile.id]);
        if (user.rows.length===0) {
            const newUser = await db.query('INSERT INTO users(username, google_id) VALUES ($1, $2)', [profile.displayName, profile.id]);
            return cb(null, profile);
        } else {
            return cb(null, profile);
        }
    } catch (error) {
        return cb(error)
    }
}
));


// Routes
// Get All Users
app.get('/api/users', async (req, res) => {
    try {
        const users = await db.query('SELECT id, username FROM users');
        // console.log(users);
        res.json({
            users:users.rows
        });
    } catch (error) {
        console.log(error);
        res.json({
            error
        })
    }
});

// Get Single User
app.get('/api/user/:id', async (req, res) => {
    const {id} = req.params;
    try {
        const user = await db.query('SELECT id, username FROM users WHERE id=$1', [id]);
        // console.log(users);
        res.json({
            user:user.rows[0]
        });
    } catch (error) {
        console.log(error);
        res.json({
            error
        })
    }
});

// Create New User
app.post('/api/users', (req, res) => {
    const {username, password} = req.body
    bcrypt.hash(password, saltRounds, async (err, hash) => {
        if(!err){
            try {
                const user = await db.query('INSERT INTO users(username, password) VALUES ($1, $2) RETURNING id, username', [username, hash]);
                res.json({
                    user: user.rows[0]
                });
            } catch (error) {
                res.json({
                    error
                });
            }
        } else {
            res.json({
                error: err
            });
        }
    });
});

// Update User
app.put('/api/user/:id', async (req, res) => {
    const {id} = req.params;
    const {username, password} = req.body;
    try {
        const user = await db.query('UPDATE users SET username=$1, password=$2 WHERE id=$3 RETURNING id, username', [username, password, id]);
        res.json({
            user: user.rows
        });
    } catch (error) {
        console.log(error);
        res.json({
            error
        });
    }
});

// Delete User
app.delete('/api/user/:id', async (req, res) => {
    const {id} = req.params;
    try {
        const user = await db.query('DELETE FROM users WHERE id=$1', [id]);
        res.json({
            status: "success"
        });
    } catch (error) {
        console.log(error);
        res.json({
            error
        });
    }
});

//Login User
app.post('/api/login', (req, res, next) => {
    passport.authenticate('local', { session: false }, async (err, user, info) => {
        if (!err) {
            const token = jwt.sign({user: user}, process.env.JWT_SECRET, {expiresIn: '4h'});
            res.json({
                authStatus: true,
                token
            }); 
        } else {
            res.json({error: err});
        }
    })(req, res, next);
});

app.get('/auth/google', passport.authenticate('google', {session:false, scope:['profile']}));
app.get('/auth/google/callback', passport.authenticate('google', {session: false}), (req, res) => {
    const token = jwt.sign({user: req.user}, process.env.JWT_SECRET, {expiresIn: '4h'});
    res.json({
        authStatus: true,
        token
    }); 
});

// Logout User
app.get('/api/logout', (req, res) => {
    console.log(req.user);
    req.logout();
});

// Verify Token
app.get('/api/verify', verifyToken, (req, res) => {
    console.log('verify token test');
});


app.listen(PORT, ()=>console.log(`Server Started on port ${PORT}`));