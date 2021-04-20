const express = require('express')
const mongoose = require('mongoose')
const passport = require('passport')
const User = require('./models/User')
const { route } = require('./routes/')

// mongoose.connect('mongodb://127.0.0.1:27017/passport-jwt', { useMongoClient: true })
mongoose.connect('mongodb://127.0.0.1:27017/passport-jwt', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).catch(error => console.log(error))
mongoose.set('useCreateIndex', true)
// mongoose.connection.on('error', (error) => { console.log(err) })
mongoose.Promise = global.Promise
require('./auth')
const routes = require('./routes/')
const secureRoute = require('./routes/secureRoute')

const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use('/', routes)
/**
 * plug in JWT Strategy as a middleware so only verified users can access this route
 */
app.use('/user', passport.authenticate('jwt', { session: false }), secureRoute)
// Handle errors.
app.use((err, req, res, next) => {
  res.status(err.status || 500)
  res.json({ error: err })
})

app.listen(3000, () => {
  console.log('Server started.')
})
