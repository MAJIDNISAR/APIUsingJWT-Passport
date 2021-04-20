const passport = require('passport')
const localStrategy = require('passport-local').Strategy
const JWTstrategy = require('passport-jwt').Strategy
const ExtractJWT = require('passport-jwt').ExtractJwt
const User = require('../models/User')

/**
 * Passport middleware to handle user registration:
 */
passport.use('signup', new localStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    let user = await User.findOne({ email })
    if (!user) {
      user = await User.create({ email, password })
      console.log('passport signup===========')
      console.log(user)
      return done(null, {
        message: 'Signup Successful!',
        User: user
      })
    } else {
      console.log('User Already exists', user)
      return done(null,
        {
          message: 'User Already Exits',
          User: user.email
        })
    }
  } catch (error) {
    console.log('error====', error)
    done(error)
  }
}))

/**
 *  Passport middleware to handle user login
 */
passport.use('login', new localStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    const user = await User.findOne({ email })
    if (!user) return done(null, false, { message: 'User not Found! Please check email' })
    const validate = await user.isValidPassword(password)
    if (!validate) {
      return done(null, false, { message: 'Error: Incorrect Passpor - Please check passord' })
    }
    return done(null, user, { message: 'Logged in Successfully' })
  } catch (error) {
    console.log('login error====', error)
    return done(error)
  }
}
))

/**
 * Verifying the JWT
 */
passport.use(new JWTstrategy({
  secretOrKey: 'MyTopSecretForSigningJWT@999',
  jwtFromRequest: ExtractJWT.fromUrlQueryParameter('secret_token')
}, async (token, done) => {
  try {
    return done(null, token.user)
  } catch (error) {
    return done(error)
  }
}))
