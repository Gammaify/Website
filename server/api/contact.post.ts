
import { SentMessageInfo } from 'nodemailer';
import nodemailer from 'nodemailer';

export default defineEventHandler(async (event) => {
    
    const data = await readBody(event);

    try{

        var transport = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: 587,
            auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
            }
    });

    var mailOptions = {
        from:  process.env.SMTP_USER,
        to: 'oliver@gammaify.com',
        subject: 'Contact Us Emails',
        html: `<p>Name: ${data.name}</p>
               <p>Email: ${data.email}</p>
               <p>Message: ${data.message}</p>`,
    };

        transport.sendMail(mailOptions, (error: Error|null, info: SentMessageInfo) => {
            if (error) {
                console.log(error);
                 return 'error'
            }
           
        });
        
         return 'success'
    } catch(err) {
        console.log(err)
       return 'error'
    }
})