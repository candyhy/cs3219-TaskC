const User = require('../models/User');
const crypto = require('crypto');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const messages = require('../common/messages');

const secretKey = 'TASKC_SECRET_KEY';

const hasMissingUserNameField = (req) => {
	return req.body.username == undefined || req.body.username.length == 0;
}

const hasMissingPasswordField = (req) => {
	return req.body.password == undefined || req.body.password.length == 0;
};

const hasMissingAuthFields = (req) => {
	return Object.keys(req.body).length == 0; 
};

const checkMissingToken = (token, res) => {
	if (!token) {
		return res
		.status(401)
		.json({
			status: messages.failureResponse,
			data: {
				message: messages.missingJwtToken
			}
		});
	}
}


const isPasswordAndUserMatch = (req, res) => {
	const username = req.body.username;
	User.find({username: username})
        .then((result) => {
            if (Object.keys(result).length == 0) {
				res.status(400).send({
            		status: messages.failureResponse,
            		data: {
                		message: messages.invalidUserName + username
            		}
        		});
        		return;
			}
			
			data = result[0];
			const permissionLevel = data.permissionLevel;
			let passwordFields = data.password.split('$');
        	let salt = passwordFields[0];
        	let hash = crypto.createHmac('sha512', salt).update(req.body.password).digest("base64");
			if (hash == passwordFields[1]) {
				const token = jwt.sign(
					{
						username: username,
						permissionLevel: permissionLevel
					},
					secretKey,
					{
						expiresIn: "168h",
					}
				); 

        		res.status(200).cookie("taskc_jwt", token, {
            			httpOnly: true
            		}).json({
   					status: messages.successResponse, 
    				data: {
    					username: username,
        				message: messages.validUserLogin
    				}
  				  });
   				return;
   			} else {
           		res.status(400).send({
           			status: messages.failureResponse,
           			data: {
           				message: messages.invalidPassword
            		}
            	});
            	return;
        	}
			
        });
};

exports.create_account = (req, res) => {

	if (hasMissingAuthFields(req)) {
		res.status(400).send({
			status: messages.failureResponse,
			data: {
				message: messages.missingAuthFields
			}
		});
		return;
	}

	if (hasMissingUserNameField(req)) {
		res.status(400).send({
			status: messages.failureResponse,
			data: {
				message: messages.missingUserName
			}
		});
		return;

	}

	if (hasMissingPasswordField(req)) {
		res.status(400).send({
			status: messages.missingUserName,
			data: {
				message: messages.missingPasswordField
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
						status: messages.successResponse,
						data: {
							message: messages.createAccountSuccess
						}
					});
					return;    
					});  		
        	} else {
				res.status(404).send({
            		status: messages.failureResponse,
            		data: {
                		message: messages.userExists + username
            		}
        		});
        		return;
			}
		}).catch((err) => {
             res.status(500).json({
                 status: messages.errorResponse,
                 error_message: messages.dbWriteError
             });
         });
         return;
};

exports.user_login = (req, res) => {
	if (hasMissingAuthFields(req)) {
		res.status(400).send({ 
			status: messages.failureResponse,
			data: {
				message: messages.missingAuthFields
			}
		});
		return;
	}

	if (hasMissingUserNameField(req)) {
		res.status(400).send({
			status: messages.failureResponse,
			data: {
				message: messages.missingUserName
			}
		});
		return;
	}

	if (hasMissingPasswordField(req)) {
		res.status(400).send({
			status: messages.failureResponse,
			data: {
				message: messages.missingPasswordField
			}
		});
		return;
	}

	return isPasswordAndUserMatch(req, res);
};

exports.user_logout = (req, res) => {
	res.status(200).clearCookie("taskc_jwt")
	.json({
		status: messages.successResponse, 
    	data: {
        	message: messages.userLogOutSuccess
    	}
    });
};
exports.validate_jwt = (req, res) => {
    const token = req.cookies.taskc_jwt;
    try {
        checkMissingToken(token, res);
    
        jwt.verify(token, secretKey, (err, user) => {
            if (err) {
                console.log(err);
                return res
                .status(401)
                .json({
                    status: messages.failureResponse,
                    message: messages.invalidJwtToken
                });
            }
            req.user = user;
			res.status(200).send({
				status: messages.successResponse,
				data: {
					username: user.username
				}
			});
			return;
        });
    } catch (error) {
        res.status(500).send({
			status: messages.errorResponse,
			data: {
				message: JWT_ERROR(error)
			}
		});
    }
}

exports.create_admin = (req, res) => {
 	if (hasMissingAuthFields(req)) {
		res.status(400).send({
			status: messages.failureResponse,
			data: {
				message: messages.missingAuthFields
			}
		});
		return;
	}

	if (hasMissingUserNameField(req)) {
		res.status(400).send({
			status: messages.failureResponse,
			data: {
				message: messages.missingUserName
			}
		});
		return;

	}

	if (hasMissingPasswordField(req)) {
		res.status(400).send({
			status: messages.missingUserName,
			data: {
				message: messages.missingPasswordField
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
 				req.body.permissionLevel = 2;
 				const permissionLevel = req.body.permissionLevel;

 				const user = new User({
					username : username,
					password : password,
					permissionLevel : permissionLevel
				});
 				user.save().then((result) => {
 					res.status(201).send({
 						status: messages.successResponse,
 						data: {
 							message: messages.createAdminSuccess
 						}
 					});
 					return;    
 					});  		
         	} else {
 				res.status(404).send({
             		status: responseStatus.FAILURE,
             		data: {
                 		message: messages.userExists + email
             		}
         		});
         		return;
 			}
 		}).catch((err) => {
              res.status(500).json({
                  status: messages.errorResponse,
                  error_message: messages.dbWriteError
              });
          });
          return;
 }

 exports.validate_admin = (req, res) => {
     const token = req.cookies.taskc_jwt;
     try {
         checkMissingToken(token, res);

         jwt.verify(token, secretKey, (err, user) => {
             if (err) {
                 console.log(err);
                 return res
                 .status(401)
                 .json({
                     status: messages.failureResponse,
                     message: messages.invalidJwtToken
                 });
             }
             req.user = user;
             const role = user.permissionLevel === 1 ? "user" : "admin";
             console.log(user.permissionLevel);
             if (role === "admin") {
             	res.status(200).send({
 					status: messages.successResponse,
 					data: {
 						message: messages.validAdmin
 					}
 				});
 				return;
             } else {
             	res.status(403).send({
             		status: messages.failureResponse,
             		data: {
             			message: messages.invalidAdmin
             		}
             	})
             	return;
             }
         });
     } catch (error) {
         res.status(500).send({
 			status: messages.errorResponse,
 			data: {
 				message: JWT_ERROR(error)
 			}
 		});
     }
 }