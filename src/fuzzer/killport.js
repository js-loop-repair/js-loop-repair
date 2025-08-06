const killport = require("killport");

function fuzz(buf) {
  killport(8080)
    .then(function (out) {
      console.log(out);
    })
    .catch(function (err) {
      throw err;
    });
}

module.exports = {
  fuzz,
};
