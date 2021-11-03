const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema({
	username: {
		type: String,
		unique: true,
		required: true,
	},
	password: {
		type: String,
		required:true,
	},
	permissionLevel: Number
});

userSchema.virtual('id').get(function() {
	return this._id.toHexString();
});

userSchema.set('toJSON', {
	virtuals:true
});

const User = mongoose.model('User', userSchema);
module.exports = User;
