const nodemailer = require('nodemailer');
const config = require('./emailconfig.json');

const transporter = nodemailer.createTransport(config.smtp);

async function sendCode(to, code, ip, subject = config.subject) {
  const msg = {
    from: config.from,
    to,
    subject,
    text: config.template
      .replace('{code}', code)
      .replace('{ip}', ip)
  };
  console.log('[sendCode] 准备发送邮件:', msg);
  try {
    console.log('[sendCode] 调用 transporter.sendMail...');
    const info = await transporter.sendMail(msg);
    console.log('[sendCode] 邮件已发送:', info);
  } catch (err) {
    console.error('[sendCode] 发送邮件出错:', err);
    throw err;
  }
}

module.exports = { sendCode };
