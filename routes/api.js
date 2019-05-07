const router = require('express').Router();
const Usercontroller = require('../controllers/user');
const bodyParser = require("body-parser");
router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());
router.post('/signin',Usercontroller.signin);
router.post('/signup', Usercontroller.signup);
router.get('/verify',Usercontroller.verify);
module.exports = router;