import {defineCronHandler } from '#nuxt/cron'
import { SentMessageInfo } from 'nodemailer';
import nodemailer from 'nodemailer';
import mysql, { ConnectionOptions } from 'mysql2/promise';

const access: ConnectionOptions = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
};

interface emailData {
    create_time: Date,
    name: string
    email: string
    message: string
    email_sent: boolean
}

async function sendEmail(data: emailData[], connection: mysql.Connection) {

    let table = '<table cellspacing="10" style="border: 1px solid; border-collapse: collapse;"><tr><th>Date/Time</th><th>Name</th><th>Email</th><th>Message</th></tr>';


    data.forEach(element => {
        table += `<tr><td style='border:1px solid; padding:10px'>${element.create_time}</td><td style='border:1px solid; padding:10px'>${element.name}</td><td style='border:1px solid; padding:10px'>${element.email}</td><td style='border:1px solid; padding:10px'>${element.message}</td></tr>`
    });

    table += '</table>'

    var transport = nodemailer.createTransport({
        host: "in-v3.mailjet.com",
        port: 587,
        auth: {
        user: process.env.SMTP_APIKEY,
        pass: process.env.SMTP_SECRETKEY
        }
    });

    var mailOptions = {
        from: '"Support Team" <noreply@gammaify.com>',
        to: 'oliver@gammaify.com',
        subject: 'Contact Us Emails',
        html: table,
    };

     transport.sendMail(mailOptions, (error: Error|null, info: SentMessageInfo) => {
        if (error) {
            return console.log(error);
        }
        else{
            try{
                connection.query(
                    'UPDATE contacts SET email_sent = 1 WHERE email_sent = 0'
                ) 
                console.log('Successfully sent');
            }
            catch(err){
                console.log(err)
            }
                  
            
        }
    });
}

export default defineCronHandler('everySixHours', async () => {

    const connection = await mysql.createConnection(access);

    try{
        const [results] =  await connection.query(
            'SELECT * FROM contacts WHERE email_sent = 0'
        )  
        var resultJson = JSON.parse(JSON.stringify(results));
        if (resultJson.length > 0) {
            await sendEmail(resultJson, connection)
        }
    }
    catch(err){
        console.log(err)
    }

    
})