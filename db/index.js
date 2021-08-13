const {Pool} = require('pg');
const connectionString = process.env.NODE_ENV === 'production' ? process.env.DATABASE_URL : process.env.PG_URI;

const pool = new Pool({
    connectionString,
    ssl: true
});

module.exports = {
    query: (text, params) => pool.query(text, params),
}