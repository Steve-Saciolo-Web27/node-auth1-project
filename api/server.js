const express = require('express')
const helmet = require('helmet')
const morgan = require('morgan')
const cors = require('cors')
const session = require('express-session')

const usersRouter = require('../users/users-router')
const authRouter = require('../auth/router')
const restricted = require('../auth/restricted-middleware')

const server = express()

const sessionConfig = {
  name: 'monster',
  secret: 'keep it secret, keep it safe',
  cookie: {
    maxAge: 1000 * 60 * 60,
    secure: false, // true in production to send only over https
    httpOnly: true //true means no access from JS
  },
  resave: false,
  saveUninitialized: true //GDPR laws require to check with client
}

server.use(helmet())
server.use(morgan('dev'))
server.use(express.json())
server.use(cors())
server.use(session(sessionConfig))

server.use('/api/users', restricted, usersRouter)
server.use('/api/auth', authRouter)

server.get('/', (req, res) => {
  res.send('We up')
})

module.exports = server
