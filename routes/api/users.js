const express = require('express')
const router = express.Router()
const {body, validationResult} = require('express-validator') //подключение проверки
const gravatar = require('gravatar')
const bcrypt = require('bcryptjs')
const User = require('../../models/User')
const jwt = require('jsonwebtoken')
const config = require('config')


// @route POST api/users
// @desc Register user
// @access Public
router.post(
  '/',
  body('name', 'Name is required').not().isEmpty(),
  body('email', 'Please include a valid Email').isEmail(),
  body('password', 'Please enter a password with 6 or more characters').isLength({min: 6}),
  async (req, res) => {
    //console.log(req.body)
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.status(400).json({errors: errors.array()})
    }

    const {name, email, password} = req.body

    try {
      //See if user exists
      let user = await User.findOne({email})
      if (user) {
        return res.status(400).json({errors: [{msg: 'User already exists'}]})
      }


      //Get users gravatar
      const avatar = gravatar.url(email, {
        s: '200',
        r: 'pg',
        d: 'mm'
      })

      user = new User({
        name,
        email,
        avatar,
        password
      })

      //Encrypt password
      const salt = await bcrypt.genSalt(10)
      user.password = await bcrypt.hash(password, salt)

      await user.save();
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

