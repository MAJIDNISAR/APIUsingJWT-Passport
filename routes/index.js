const express = require('express')
const passport = require('passport')
const jwt = require('jsonwebtoken')
const { Error } = require('mongoose')

const router = express.Router()
router.post('/signup', passport.authenticate('signup', { session: false }), async (req, res, next) => {
  // console.log(req.user)
  res.status(200).json({
    message: res.message,
    user: req.user
  })
})

router.post('/login', async (req, res, next) => {
  passport.authenticate('login', async (err, user, info) => {
    try {
      if (err || !user) {
        const error = new Error('An Error occured!')
        return next(error)
      }
      req.login(
        user,
        { session: false },
        async (error) => {
          if (error) return next(error)
          const body = { _id: user.id, email: user.email }
          const token = jwt.sign({ user: body }, 'MyTopSecretForSigningJWT@999')
          return res.status(200).json({ token })
        }
      )
    } catch (error) {
      return next(error)
    }
  })(req, res, next)
})

module.exports = router
