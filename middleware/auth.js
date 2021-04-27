const jwt = require('jsonwebtoken')
const config = require('config')

module.exports = function (req, res, next) {
//Get token from header
  console.log(req.header('x-auth-token'))
  const token = req.header('x-auth-token')
  if (!token) {
    return res.status(401).json({msg: 'No token, authorization denied'})
  }

  //Verify token
  try {
    const decoded = jwt.verify(token, config.get('jwtSecret'));
    req.user = decoded.user
    //console.log(req.user)
    next()
  } catch (e) {
    res.status(401).json({msg: 'Token is not valid'})
  }
}
