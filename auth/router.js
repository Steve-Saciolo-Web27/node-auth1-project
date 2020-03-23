const bcrypt = require('bcryptjs')
const router = require('express').Router()

const Users = require('../users/users-model')

router.post('/register', (req, res) => {
  const userInfo = req.body

  const ROUNDS = process.env.ROUNDS || 16

  // Password will be hashed and re-hashed 2 ^ 8 times
  const hash = bcrypt.hashSync(userInfo.password, ROUNDS)

  userInfo.password = hash

  Users.add(userInfo)
    .then(user => {
      res.json(user)
    })
    .catch(err => res.send(err))
})

router.post('/login', (req, res) => {
  const { username, password } = req.body

  Users.findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = {
          id: user.id,
          username: user.username
        }
        res.status(200).json({ hello: user.username })
      } else {
        res.status(401).json({ message: 'invalid credentials' })
      }
    })
    .catch(error => {
      res.status(500).json({ errorMessage: 'error finding the user' })
    })
})

router.get('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(error => {
      if (error) {
        res.status(500).json({
          message:
            'you can check out any time you like, but you can never leave'
        })
      } else {
        res.status(200).json({ message: 'logged out successfully' })
      }
    })
  } else {
    res.status(200).json({ message: 'Who knows you' })
  }
})

module.exports = router
