
# Sherpa authentication services

===================

This is a tack on for the video sherpa editor.

Has authentication services for Facebook, YouTube and Twitter currently. Further implementation planned are LinkedIn and Instagram

====================

# Getting the authentication service up and running

Helpful links:

[Getting an SSL Certificate](https://letsencrypt.org/).

[Another step by step guide](http://timmyreilly.azurewebsites.net/running-flask-on-ubuntu-vm/).

Minimum software:

gunicorn3

flask

nginx

Ubuntu

pip3

python3

Install dependencies using requirements.txt

Install flow:

- You need to have an SSL Certificate installed on your server, otherwise YouTube's Authentication service will NOT work.

- A free one can be installed from [here](https://letsencrypt.org/).

- We used gunicorn as our Web Server Gateway Interface.

- We used nginx as our web server.

- We used flask to write the website itself.

- The flask app is python 3 specific. So you need to use gunicorn3.

- We run the flask apps on Ubuntu, but any VM will be suitable.

- Make sure you have ports opened for the flask app. If you're using Azure, you can open them in the panel (Network Security group for resource group with vm -> settings -> Inbound Security Rules). port 5000 is for development environmnet, 8000 is for production.

- Set up environment for flask, for tutorial purpose, we have put our flask app inside a folder called `Flask_Server`

- Once flask is set up, you need to set up nginx and gunicorn3(`$ sudo apt-get install -y nginx gunicorn3`)

- Once nginx is installed, start it (`$ sudo /etc/init.d/nginx start`)

- Then we need to configure nginx to run our app. Add our app to nginx using these three commands:

```Shell
// Remove default setting
$ sudo rm /etc/nginx/sites-enabled/default

// Add our flask app to the sites available
$ sudo touch /etc/nginx/sites-available/Flask_Server

// Creates a symbiotic link of the first directory in the second directory 
$ sudo ln -s /etc/nginx/sites-available/Flask_Server /etc/nginx/sites-enabled/Flask_Server
```

- Open `/etc/nginx/sites-enabled/Flask_Server` in a text editor of your choice. Copy paste the text below

```Shell
server {
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    location /static {
        alias /Flask_Server/static/;  
    }
}
```

- restart the server (`$ sudo /etc/init.d/nginx restart`)

- Navigate to the `Flask_Server` Directory

- Then to run the app: `$sudo gunicorn3 app:app -b 0.0.0.0:8000 --reload`

- This will run the flask app at `(IP.ADDRESS.OF.VM):8000`

- Installing certbot to get SSL Certificate

- Run the following commands to install Certbot PPA:

```Shell
// Update
$ sudo apt-get update

// Prerequisite installs
$ sudo apt-get install software-properties-common

$ sudo add-apt-repository universe

// Certbot PPA
$ sudo add-apt-repository ppa:certbot/certbot

// Final update
$ sudo apt-get update
```

- Then install certbot using `sudo apt-get install certbot python-certbot-nginx`

- You can either use `sudo certbot --nginx` to edit the nginx file automatically to include the certificate or `sudo certbot certonly --nginx` if you wish to only install the certificate. The command below assumes you used the first command, but both commands should be acceptable

- Running the app with the letsencrypt SSL cert: `$sudo gunicorn3 app:app -b 0.0.0.0:8010 --reload --timeout 120 --certfile /etc/letsencrypt/live/test_vm.westeurope.cloudapp.azure.com/cert.pem --keyfile /etc/letsencrypt/live/test_vm.westeurope.cloudapp.azure.com/privkey.pem`
