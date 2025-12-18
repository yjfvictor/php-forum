# Deployment Instructions

## Quick Start

### 1. Initialize the Project

```bash
# Navigate to project directory
cd php_forum

# Create data directory with proper permissions
mkdir -p data
chmod 777 data  # Or set appropriate ownership for your web server user

# Initialize admin account
php backend/init.php
```

### 2. Compile TypeScript

```bash
cd frontend
tsc
cd ..
```

### 3. Deploy to Web Server

#### Option A: PHP Built-in Server (Development/Testing)

```bash
cd backend
php -S localhost:8000 router.php
```

Access the forum at: `http://localhost:8000`

**Note**: The `router.php` script is required to properly route requests to both backend and frontend files when using PHP's built-in server.

#### Option B: Apache

1. **Copy files to web server directory**:
   ```bash
   cp -r php_forum/* /var/www/html/forum/
   ```

2. **Set permissions**:
   ```bash
   chmod 755 /var/www/html/forum/backend
   chmod 755 /var/www/html/forum/frontend
   chmod 777 /var/www/html/forum/data
   ```

3. **Create `.htaccess` in backend directory**:
   ```apache
   RewriteEngine On
   RewriteCond %{REQUEST_FILENAME} !-f
   RewriteCond %{REQUEST_FILENAME} !-d
   RewriteRule ^(.*)$ index.php [QSA,L]
   ```

4. **Configure Apache virtual host** (optional):
   ```apache
   <VirtualHost *:80>
       ServerName forum.example.com
       DocumentRoot /var/www/html/forum/backend
       
       <Directory /var/www/html/forum/backend>
           AllowOverride All
           Require all granted
       </Directory>
   </VirtualHost>
   ```

5. **Access the forum** at your server URL

#### Option C: Nginx

1. **Copy files to web server directory**:
   ```bash
   cp -r php_forum/* /var/www/html/forum/
   ```

2. **Set permissions**:
   ```bash
   chmod 755 /var/www/html/forum/backend
   chmod 755 /var/www/html/forum/frontend
   chmod 777 /var/www/html/forum/data
   ```

3. **Create Nginx configuration**:
   ```nginx
   server {
       listen 80;
       server_name forum.example.com;
       root /var/www/html/forum/backend;
       index index.php;

       location / {
           try_files $uri $uri/ /index.php?$query_string;
       }

       location ~ \.php$ {
           fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
           fastcgi_index index.php;
           include fastcgi_params;
           fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
       }
   }
   ```

4. **Reload Nginx**:
   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   ```

5. **Access the forum** at your server URL

## Verification Steps

1. **Check admin login**:
   - Username: `admin`
   - Password: `admin123`

2. **Test features**:
   - Create a new user account
   - Create a thread
   - Reply to a thread
   - Access admin panel (as admin)
   - Change password
   - Delete posts

3. **Check file permissions**:
   ```bash
   ls -la data/
   # Should show credentials.json and threads.json (if threads exist)
   ```

## Troubleshooting

### Permission Errors

If you see permission errors when creating users or threads:

```bash
# Fix data directory permissions
chmod 777 data
# Or set ownership to web server user
chown -R www-data:www-data data
```

### TypeScript Not Compiled

If the frontend doesn't load:

```bash
cd frontend
tsc
# Check that dist/ directory contains .js files
ls -la dist/
```

### API Requests Failing

1. Check browser console for errors
2. Verify API path in `frontend/src/api.ts` is correct
3. Check PHP error logs
4. Ensure `data/` directory is writable

### Session Issues

1. Check PHP session configuration
2. Verify `data/` directory is writable
3. Check browser cookies are enabled
4. Ensure session cookies are being set (check browser dev tools)

## Production Considerations

1. **Security**:
   - Change admin password immediately
   - Use HTTPS
   - Set `cookie_secure => true` in `config.php` if using HTTPS
   - Restrict file permissions on `data/` directory

2. **Performance**:
   - Consider using a database instead of JSON files for production
   - Enable PHP opcode caching (OPcache)
   - Use a proper web server (Apache/Nginx) instead of built-in server

3. **Backup**:
   - Regularly backup `data/credentials.json` and `data/threads.json`
   - These files contain all user data and forum content

4. **Monitoring**:
   - Monitor PHP error logs
   - Check web server access logs
   - Monitor disk space for `data/` directory

## Environment Variables (Optional)

You can modify `backend/config.php` to use environment variables:

```php
define('DATA_DIR', getenv('FORUM_DATA_DIR') ?: __DIR__ . '/../data/');
```

Then set in your environment:
```bash
export FORUM_DATA_DIR=/path/to/data
```

