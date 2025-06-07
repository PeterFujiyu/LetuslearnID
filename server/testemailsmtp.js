const { sendCode } = require('./email');
const code = process.argv[2] || 'test';
const email = process.argv[3];
if (!email) {
  console.error('Usage: npm run testemailsmtp "code" "email"');
  process.exit(1);
}
sendCode(email, code, 'cli').then(()=>{
  console.log('Email sent');
}).catch(err=>{
  console.error(err);
  process.exit(1);
});
