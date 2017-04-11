/** @module sessions
  * a module representing a user sessions
  */

module.exports = {
  create:create,
  destroy: destroy
};

var json = require('../../lib/form-json');
var encryption = require('../../lib/encryption');

function create(req, res, db){
  json(req, res, function(req, res) {
    var username = req.body.username;
    var password = req.body.password;
    db.get("SELECT * FROM users WHERE username=?", [username], function(err, user){
      if (err){
        res.statusCode = 500;
        res.end("Server error");
        return;
      }
      if (!user){
      return;
      }
      var cryptedPassword = encryption.digest(password + user.salt);
      if (cryptedPassword != user.cryptedPassword){

      }
      else{
        var cookieData = JSON.stringify({userId: user.id});
        var encryptedCookieData = encryption.encipher(cookieData);

        res.setHeader("Set-Cookie", ["session=" + encryptedCookieData]);
        res.statusCode = 200;
        res.end("Successful Login");
      }
    });
  });
}
