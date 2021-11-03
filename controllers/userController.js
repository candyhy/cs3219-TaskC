const User = require('../models/User');
const crypto = require('crypto');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const hasMissingUserNameField = (req) => {
	return req.body.username == undefined || req.body.username.length == 0;
}

const hasMissingPasswordField = (req) => {
	return req.body.password == undefined || req.body.password.length == 0;
};

const hasMissingAuthFields = (req) => {
	return Object.keys(req.body).length == 0; 
};

const missingUserNameMessage = "Missing username field";
const missingAuthFieldsMessage = "Missing username and password fields";
const missingPasswordFieldMessage = "Missing password field"
const missingJwtTokenMessage = "Missing jwt token";
const invalidUserNameMessage = "Invalid username: ";
const invalidPasswordMessage = "Invalid Password: ";
const invalidJwtTokenMessage = "Invalid jwt token";
const userExistsMessage = "User already exists: "
const validUserLoginMessage = "Valid user login";
const createAccountSuccessMessage = "Account created successfully";
const userLogOutSuccessMessage = "User successfully logged out";
const validJwtTokenMessage = "Jwt token validation successfully";
const successResponseMessage = "success";
const failureResponseMessage = "failure";
const secretKey = 'TASKC_SECRET_KEY';
const dbWriteErrorMessage = "Error writing to database";
const dbReadErrorMessage = "Error reading from databse";
const errorResponseMessage = "error";

const isPasswordAndUserMatch = (req, res) => {
	const username = req.body.username;
	User.find({username: username})
        .then((result) => {
            if (Object.keys(result).length == 0) {
				res.status(400).send({
            		status: failureResponseMessage,
            		data: {
                		message: invalidUserNameMessage + username
            		}
        		});
        		return;
			}
			
			data = result[0];
			let passwordFields = data.password.split('$');
        	let salt = passwordFields[0];
        	let hash = crypto.createHmac('sha512', salt).update(req.body.password).digest("base64");
			if (hash == passwordFields[1]) {
				const token = jwt.sign(
					{
						username: username
					},
					secretKey,
					{
						expiresIn: "1h",
					}
				); 

        		res.status(200).cookie("taskc_jwt", token, {
            			httpOnly: true
            		}).json({
   					status: successResponseMessage, 
    				data: {
    					username: username,
        				message: validUserLoginMessage
    				}
  				  });
   				return;
   			} else {
           		res.status(400).send({
           			status: failureResponseMessage,
           			data: {
           				message: invalidPasswordMessage
            		}
            	});
            	return;
        	}
			
        });
};

exports.create_account = (req, res) => {

	if (hasMissingAuthFields(req)) {
		res.status(400).send({
			status: responseStatus.FAILURE,
			data: {
				message: missingAuthFieldsMessage
			}
		});
		return;
	}

	if (hasMissingUserNameField(req)) {
		res.status(400).send({
			status: failureResponseMessage,
			data: {
				message: missingUserNameMessage
			}
		});
		return;

	}

	if (hasMissingPasswordField(req)) {
		res.status(400).send({
			status: missingUserNameMessage,
			data: {
				message: missingPasswordFieldMessage
			}
		});
		return;
	}
	const username = req.body.username;
	User.find({username: username})
		.then((result) => {
			if (Object.keys(result).length == 0) {
				let salt = crypto.randomBytes(16).toString('base64');
				let hash = crypto.createHmac('sha512', salt).update(req.body.password).digest("base64");
				const password = salt + "$" + hash;
				req.body.permissionLevel = 1;
				const permissionLevel = req.body.permissionLevel;

				const user = new User({
					username : username,
					password : password,
					permissionLevel : permissionLevel
				});
				user.save().then((result) => {
					res.status(201).send({
						status: successResponseMessage,
						data: {
							message: createAccountSuccessMessage
						}
					});
					return;    
					});  		
        	} else {
				res.status(404).send({
            		status: responseStatus.FAILURE,
            		data: {
                		message: userExistsMessage + username
            		}
        		});
        		return;
			}
		}).catch((err) => {
             res.status(500).json({
                 status: responseStatus.ERROR,
                 error_message: dbWriteErrorMessage
             });
         });
         return;
};

exports.user_login = (req, res) => {
	if (hasMissingAuthFields(req)) {
		res.status(400).send({ 
			status: failureResponseMessage,
			data: {
				message: missingAuthFieldsMessage
			}
		});
		return;
	}

	if (hasMissingUserNameField(req)) {
		res.status(400).send({
			status: failureResponseMessage,
			data: {
				message: missingUserNameMessage
			}
		});
		return;
	}

	if (hasMissingPasswordField(req)) {
		res.status(400).send({
			status: failureResponseMessage,
			data: {
				message: missingPasswordFieldMessage
			}
		});
		return;
	}

	return isPasswordAndUserMatch(req, res);
};

exports.user_logout = (req, res) => {
	res.status(200).clearCookie("taskc_jwt")
	.json({
		status: successResponseMessage, 
    	data: {
        	message: userLogOutSuccessMessage
    	}
    });
};
exports.validate_jwt = (req, res) => {
    const token = req.cookies.taskc_jwt;
    try {
        if (!token) {
            return res
                .status(401)
                .json({
                    status: failureResponseMessage,
                    data: {
						message: missingJwtTokenMessage
					}
                });
        }
    
        jwt.verify(token, secretKey, (err, user) => {
            if (err) {
                console.log(err);
                return res
                .status(401)
                .json({
                    status: failureResponseMessage,
                    message: invalidJwtTokenMessage
                });
            }
            req.user = user;
			res.status(200).send({
				status: successResponseMessage,
				data: {
					username: user.username
				}
			});
			return;
        });
    } catch (error) {
        res.status(500).send({
			status: errorResponseMessage,
			data: {
				message: JWT_ERROR(error)
			}
		});
    }
}