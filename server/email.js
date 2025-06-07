const nodemailer = require('nodemailer');
const config = require('./emailconfig.json');

const transporter = nodemailer.createTransport(config.smtp);

async function sendCode(to, code, subject = config.subject) {
  const msg = {
    from: config.from,
    to,
    subject,
    text: config.template.replace('{code}', code)
  };
  await transporter.sendMail(msg);
}

module.exports = { sendCode };
