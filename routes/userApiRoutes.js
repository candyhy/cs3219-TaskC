const express = require('express');
const userController = require('../controllers/userController');

const router = express.Router();

router.all('/validate_jwt', userController.validate_jwt);
router.post('/create_account', userController.create_account);
router.post('/user_login', userController.user_login);
router.post('/user_logout', userController.user_logout);
router.post('/create_admin', userController.create_admin);
router.get('/validate_admin', userController.validate_admin);

module.exports = router;