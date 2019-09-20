const SEND_KEY=require('./config').SENDGRID_KEY
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(SEND_KEY);

exports.sendMassage=(email,token,goTo)=>{
  console.log("send msg fired")

  let msg;

  if(goTo==='reset'){

     msg = {
      to: email,
      from: 'shop@AK.com',
        subject: 'Password reset',
        html: `
          <p>You requested a password reset</p>
          <p>Click this <a href="http://localhost:3000/${goTo}/${token}">link</a> to set a new password.</p>
        `
    };

  }else{
     msg = {
        to: email,
        from: 'shop@AK.com',
          subject: 'confirm Email',
          html: `
            <p>you signup sucessfuly </p>
            <p>Click this <a href="http://localhost:3000/${goTo}/${token}">link</a> to confirm your acount.</p>
          `
      };
    }
      sgMail.send(msg)
      .then((result)=>{
          console.log("massage sent ")
          
          
      }).catch(err=>{
        console.log("error fired from send massage")
        console.log(err)
      })


}