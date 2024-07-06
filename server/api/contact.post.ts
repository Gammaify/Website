
import { SentMessageInfo } from 'nodemailer';
import nodemailer from 'nodemailer';
import mysql, { ConnectionOptions } from 'mysql2/promise';

const access: ConnectionOptions = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
};





export default defineEventHandler(async (event) => {
    
    const data = await readBody(event);


    const connection = await mysql.createConnection(access);
    //const query = getQuery(event);
    try{
        const [results] = await connection.query(
            'INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)',
            [data.name, data.email, data.message]
        )  
        var resultJson = JSON.parse(JSON.stringify(results));
        if (resultJson.affectedRows > 0) {
            return 'success'
        }
        else{
            return 'error'
        }
        
        
    } catch(err) {
       return 'error'
    }


    // var transport = nodemailer.createTransport({
    //     host: "localhost",
    //     port: 587,
    //     auth: {
    //     user: "smtp@gammaify.com",
    //     pass: "Megaquest1"
    //     }
    // });

    // var mailOptions = {
    //     from: '"Support Team" <noreply@gammaify.com>',
    //     to: 'oliver@gammaify.com',
    //     subject: 'Test Email',
    //     html: 'Test email sent successfully.',
    // };

    // transport.sendMail(mailOptions, (error: Error|null, info: SentMessageInfo) => {
    //     if (error) {
    //         return console.log(error);
    //     }
    //     console.log('Successfully sent');
    // });
})