const {Pool} = require('pg');
const connectionString = process.env.PG_URI;

const pool = new Pool({connectionString});

module.exports = {
    query: (text, params) => pool.query(text, params),
}