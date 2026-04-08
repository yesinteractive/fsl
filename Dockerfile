FROM alpine:3.20
MAINTAINER yes!nteractvie - http://yes-interactive.com

# Install modules and updates
RUN apk update \
    && apk --no-cache add \
        openssl \
        apache2 \
        apache2-ssl \
        apache2-http2 \
        git \
        unzip \
    # Install PHP 8.x runtime and extensions
    && apk --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/v3.20/community add \
        php83 \
        php83-apache2 \
        php83-bcmath \
        php83-bz2 \
        php83-calendar \
        php83-common \
        php83-ctype \
        php83-curl \
        php83-dom \
        php83-mbstring \
        php83-memcached \
        php83-mysqli \
        php83-opcache \
        php83-openssl \
        php83-pdo \
        php83-pdo_mysql \
        php83-pdo_sqlite \
        php83-phar \
        php83-session \
        php83-sockets \
        php83-xml \
        php83-xmlreader \
    && rm /var/cache/apk/* \
    && ln -sf /usr/bin/php83 /usr/bin/php \
    # Run required config / setup for apache
    # Ensure apache can create pid file
    && mkdir /run/apache2 \
    # Fix group
    && sed -i -e 's/Group apache/Group www-data/g' /etc/apache2/httpd.conf \
    # Fix ssl module
    && sed -i -e 's/LoadModule ssl_module lib\/apache2\/mod_ssl.so/LoadModule ssl_module modules\/mod_ssl.so/g' /etc/apache2/conf.d/ssl.conf \
    && sed -i -e 's/LoadModule socache_shmcb_module lib\/apache2\/mod_socache_shmcb.so/LoadModule socache_shmcb_module modules\/mod_socache_shmcb.so/g' /etc/apache2/conf.d/ssl.conf \
    # Enable modules
    && sed -i -e 's/#LoadModule rewrite_module modules\/mod_rewrite.so/LoadModule rewrite_module modules\/mod_rewrite.so/g' /etc/apache2/httpd.conf \
    # Change document root to /app
    && mkdir /app && chown -R apache:apache /app \
    && sed -i -e 's/\/var\/www\/localhost\/htdocs/\/app/g' /etc/apache2/httpd.conf \
    && sed -i -e 's/\/var\/www\/localhost\/htdocs/\/app/g' /etc/apache2/conf.d/ssl.conf \
    # Allow for custom apache configs
    && mkdir /etc/apache2/conf.d/custom \
    && echo '' >> /etc/apache2/httpd.conf \
    && echo 'IncludeOptional /etc/apache2/conf.d/custom/*.conf' >> /etc/apache2/httpd.conf \
    # Fix modules
    && sed -i 's#AllowOverride None#AllowOverride All#' /etc/apache2/httpd.conf \
    && sed -i -e 's/ServerRoot \/var\/www/ServerRoot \/etc\/apache2/g' /etc/apache2/httpd.conf \
    && mv /var/www/modules /etc/apache2/modules \
    && mv /var/www/run /etc/apache2/run \
    && mv /var/www/logs /etc/apache2/logs \
    # Empty /var/www and add an index.php to show phpinfo()
    && rm -rf /var/www/* \
    && echo '<?php phpinfo(); ?>' >  /app/phpinfo.php \
    && wget https://github.com/yesinteractive/fsl/archive/master.zip -P /app  \
    && unzip /app/master.zip -d /app \
    && rm -rf /app/master.zip \
    && cp -r /app/fsl-master/. /app \
    && rm -rf /app/fsl-master

WORKDIR /app

# Export http and https
EXPOSE 80 443

# Run apache in foreground
CMD ["/usr/sbin/httpd", "-D", "FOREGROUND"]
