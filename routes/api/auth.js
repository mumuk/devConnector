const express = require('express')
const router = express.Router()
const bcrypt = require('bcryptjs')
const auth = require('../../middleware/auth')
const jwt = require('jsonwebtoken')
const config = require('config')
const {body, validationResult} = require('express-validator') //подключение проверки

const User = require('../../models/User')

// @route GET api/auth
// @desc Authenticate user & get token
// @access Public
router.get('/', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password')
    res.json(user)
  } catch (e) {
    console.error(e.message)
    res.status(500).send('Server Error')
  }
})


// @route POST api/auth
// @desc Authenticate user & get token
// @access Public
router.post(
  '/',
  body('email', 'Please include a valid Email').isEmail(),
  body(
    'password',
    'Password is required'
  ).exists(),
  async (req, res) => {
    //console.log(req.body)
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.status(400).json({errors: errors.array()})
    }

    const {email, password} = req.body

    try {
      //See if user exists
      let user = await User.findOne({email})

      if (!user) {
        return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]})
      }

      //Compare existing and received password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]})
      }

      //Return jsonwebtoken
      const payload = {
        user: {
          id: user.id
        }
      }

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        {expiresIn: 36000},
        (e, token) => {
          if (e) throw e;
          res.json({token})
        }
      )

    } catch (e) {
      console.log(e.message)
      return res.status(500).send('Server error')
    }
  })


module.exports = router