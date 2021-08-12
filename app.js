require('dotenv').config();
const express = require('express');
const db = require('./db/index');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');

const app = express();  
const PORT = process.env.PORT || 5000;

// Middlewares
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(passport.initialize());

function extractToken(req, res, next){
    let bearerHeader = req.headers.authorization;
    if (typeof bearerHeader !== undefined) {
        let bearer = bearerHeader.split(' ');
        const token = bearer[1];
        req.token = token
        next();
    } else {
        res.status(403);
    }
}

passport.use(new LocalStrategy(async (username, password, done) => {
        try {
            const user = await db.query('SELECT * from users WHERE username=$1', [username]);
            if (user.rows.length==0) {
                return done(null, false, {message: "Incorrect Username"});
            } else {
                if (user.rows[0].password == password) {
                    return done(null, user.rows[0]);
                } else {
                    return done('Incorrect Password');
                }
            }
        } catch (error) {
            return done(error)
        }
}));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:5000/auth/google/callback"
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
app.post('/api/users', async (req, res) => {
    const {username, password} = req.body
    try {
        const user = await db.query('INSERT INTO users(username, password) VALUES ($1, $2) RETURNING id, username', [username, password]);
        // console.log(user);
        res.json({
            user: user.rows[0]
        });
    } catch (error) {
        res.json({
            error
        });
    }
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
            res.json({err});
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
app.get('/api/verify', extractToken, (req, res) => {
   jwt.verify(req.token, process.env.JWT_SECRET, (err, done) => {
       if (!err) {
           res.json({
               done
           });
       } else {
           res.json({
               err
           });
       }
   }); 
});


app.listen(PORT, ()=>console.log(`Server Started on port ${PORT}`));