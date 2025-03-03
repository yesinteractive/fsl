## FSL: Fresh Squeezed Limonade PHP Micro-Framework
![alt text](https://raw.githubusercontent.com/yesinteractive/fsl/master/public/banner-fsl.png "FSL Fresh Squeezed Limonade PHP Microframework for Microservices")

[![GitHub release](https://img.shields.io/github/release/yesinteractive/fsl?style=for-the-badge)](https://github.com/yesinteractive/fsl)
![MIT](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![PHP from Packagist](https://img.shields.io/packagist/php-v/fsl/fsl?style=for-the-badge)


FSL is an extremely lightweight and flexible PHP Micro-framework, which provides a great rapid development framework for Web apps, REST API's and Microservices.  FSL based apps work great in containerized application environments such as Docker, K8s, Openshift, and more.



### Why use FSL? ### 

Controller callbacks can be a function, an object method, a static method or a closure. See php documentation to learn more about the callback pseudo-type. This 
flexibility gives developers free range to develop class or classless based apps MVC based applications or more simpler, less structured, functional based applications. This flexibility I find is very useful
for rapid development of REST based applications and rapid development of microservices.

### FSL Extension of Limonade ###
See /lib/fsl_functions.php for a list of provided FSL functions that extend the Limonade framework (sessions management, JWT tokens, encryption, etc.)

FSL provides additional security to deal with XSS and other threats that were not addressed in the original Limonade framework.

Enjoy!

## FSL Installation ##

### With Docker ###


Docker image is Alpine 3.11 based running on Apache. The container exposes both ports 80 an 443 with a self signed certificate. If you wish to alter the container configuration, feel free to use the Dockerfile in this repo (https://github.com/yesinteractive/fsl/blob/master/Dockerfile). Otherwise, you can pull the latest image from DockerHub with the following command:
```
docker pull yesinteractive/fsl
```
Typical basic usage (below example exposes HTTP on port 8100 and HTTPS on 8143):

```
$ docker run -d \
  -p 8100:80 \
  -p 8143:443 \
  -e DADJOKES_NOECHO=FALSE \
  yesinteractive/fsl
```

Typical usage in Dockerfile:

```
FROM yesinteractive/fsl
RUN echo <your commands here>
```



### With Composer ###

It's recommended that you use [Composer](https://getcomposer.org/) to install FSL. Navigate into your project’s root directory and execute the bash command shown below. This command downloads the FSL Framework and its third-party dependencies into your project’s vendor/ directory.

```bash
$ composer require fsl/fsl 
```
You can also install FSL by referencing it in your project's `composer.json`:

```json
"fsl/fsl":">0.1"
```


This will install FSL and all required dependencies. FSL requires PHP 5.5.0 or newer.

Require the Composer autoloader into your PHP script, and you are ready to start using Slim.

```php
<?php

require 'vendor/autoload.php';

```

### Without Composer ###

If not using Composer, just download the FSL files in your web directory and be sure to include the FSL main library file:

```php
<?php

require 'lib/fsl.php';

```

## Getting Up and Running ##
> Please note that if you are using the FSL Docker image, proceed to step 5.

1. Once files are in place on web server, make sure to have URL rewriting enabled in Apache. 
2. WEB SERVER CONFIGURATION: Verify that the directory FSL is placed in on your webserver has the AllowOverride directive set to `ALL (AllowOverride All)` in the Apache `<Directory>` configuration. If this is not set then the included `.htaccess` file will not be read and routes will not be execute correctly.
3. .HTACCESS CONFIGURATION: Update the RewriteBase directive in the included `.htaccess` file to accomodate your app if it is installed in a web sub directory (not root). If installing FSL in a root web directory, then nothing needs to be changed. If you are installing FSL in a sub directory such as /foo, then make the following change to the .htaccess file: 
```
RewriteBase /foo
```

4. FSL CONFIG FILE: Edit the /config/fsl_config.php file to suit your needs. IMPORTANT: Be sure to set the correct Base URI where FSL is installed. If you are installing FSL in a sub directory on your webserver such as /foo, then make the following change to the /config/fsl_config.php file: 
```
option('base_uri', "/foo"); //set if app is not in web root directory but in a subdirectory
```
5. The code comes with an example app (index.php) with several route and countroller (/controllers/fsl_controllers.php) examples to demonstrate the flexibilty of the framework. Here are some examples of default mappings configured as examples:

HTTP Method | URL Path | Controller Function | Demo
------------ | ------------- | ------------- | -------------
GET | / | hello_world | Sample Home Page, Creates Session
GET | /api | api | Microservice Example (JSON Response)
GET | /showip | showip | Showcases encrypt/decrypt functions


6. Once configured, direct your browser to the location where you installed FSL and you should see the following:
![alt text](https://github.com/yesinteractive/fsl/blob/master/public/launchpage.png "FSL Fresh Squeezed Limonade PHP Microframework Landing Page")




---

# FSL Concepts
   
## Routes ##

Routes combine 

* an HTTP method 
* with an URL matching pattern 
* and a callback parameter

So they make the glue between an URL + a HTTP method, and the code provided in a callback controller.
```php
    dispatch('/', 'my_get_function');
    # same as dispatch_get('my_get_function');
        function my_get_function()
        {
            // Show something
            // with the code of this callback controller
        }
    
    dispatch_post('/', 'my_post_function'); 
        function my_post_function()
        {
            // Create something
        }
        
    dispatch_put('/', 'my_update_function'); 
        function my_update_function()
        {
            // Update something
        }
        
    dispatch_delete('/', 'my_delete_function'); 
        function my_delete_function()
        {
            // Delete something
        }

    dispatch_patch('/', 'my_patch_function');
        function my_patch_function()
        {
            // Patch something
        }
```

Routes are matched in the order they are declared.
The search is performed with a path given through browser URL:

    http://localhost/my_app/?u=/my/path
    http://localhost/my_app/?uri=/my/path
    http://localhost/my_app/index.php?/my/path
    http://localhost/my_app/?/my/path

When `PUT`,`DELETE` or `PATCH` methods are not supported (like in HTML form submision), you can use the `_method` parameter in `POST` requests: it will override the `POST` method.
```html
    <form action="<?php echo url_for('profile_update'); ?>" method="post">
        <p><input type="hidden" name="_method" value="PUT" id="_method"></p>
        <p>... your form fields</p>
        <p><input type="submit" value="Update"></p>
    </form>
```    

### Routing patterns and parameters ###

Patterns may include named parameters. Associated values of those parameters are available with the `params()` function.

    dispatch('/hello/:name', 'hello');
        function hello()
        {
            $name = params('name');
            return 'Hello $name';
        }

Patterns may also include wildcard parameters. Associated values are available through numeric indexes, in the same order as in the pattern.

    dispatch('/writing/*/to/*', 'my_letter');
        function my_letter()
        {
            # Matches /writing/an_email/to/joe
            $type = params(0); # "an_email"
            $name = params(1); # "joe"
            # ...
        }
        
    dispatch('/files/*.*', 'share_files');
        function share_files()
        {
            # matches /files/readme.txt
            $ext = params(1);
            $filename = params(0).".".$ext;
            # ...
        }

Unlike the simple wildcard character `*`, the double wildcard character `**` specifies a string that may contain a `/`

    dispatch('/files/**', 'share_files')
        function share_files()
        {
            # Matches /files/my/own/file.txt
            $filename = params(0); # my/own/file.txt
        }

Pattern may also be a regular expression if it begins with a `^`

    dispatch('^/my/own/(\d+)/regexp', 'my_func');
        function my_func()
        {
            # matches /my/own/12/regexp
            $num = params(0);
        }
        
Wildcard parameters and regular expressions may be named, too.

    dispatch(array('/say/*/to/**', array("what", "name")), 'my_func');
        function my_func()
        {
            # Matches /say/hello/to/joe
            $what = params('what');
            $name = params('name');
        }

You can also provide default parameter values that are merged with and overriden by the pattern parameters.

    $options = array('params' => array('firstname'=>'bob'));
    dispatch('/hello/:name', 'hello', $options);
        function hello($firstname, $name) # default parameters first
        {
            return 'Hello $firstname $name';
        }


### Callback controllers ###

The callback can be a function, an object method, a static method or a closure.
See [php documentation](http://php.net/manual/en/language.pseudo-types.php#language.types.callback) to learn more about the callback pseudo-type.

    # will call my_hello_function() function
    dispatch('/hello', 'my_hello_function');

    # Static class method call, MyClass::hello();
    dispatch('/hello', array('MyClass', 'hello'));

    # Object method call, $obj->hello();
    dispatch('/hello', array($obj, 'hello'));

    # Static class method call (As of PHP 5.2.3), MyClass::hello();
    dispatch('/hello', 'MyClass::hello');

    # Using lambda function (As of PHP 5.3.0)
    dispatch('/hello', function(){
      return 'Hello World!';
    });

Callback controllers return the rendered view output (see _Views and templates_).

They can take the pattern parameters as arguments

    dispatch('/hello/:firstname/:name', 'hello');
        function hello($firstname, $name)
        {
            # $firstname parameter equals params('firstname');
            # and $name parameter equals params('name');
            return 'Hello $firstname $name';
        }
  

Callbacks called by routes can be written anywhere before the execution of the `run()` function. They can also be grouped in controller files stored in a `controllers/` folder.

    /                   # site root
     - index.php        # file with routes declarations and run()
     + controllers/
         - blog.php     # functions for blog: blog_index(), blog_show(),
                        #  blog_post()...
         - comments.php # comments_for_a_post(), comment_add()...



This folder location can be set with the `controllers_dir` option.

    option('controllers_dir', dirname(__FILE__).'/other/dir/for/controllers');
    

You can also define `autoload_controller` function to load controllers in your own way:

    function autoload_controller($callback) 
    { 
       # If $callback, the callback function defined in matching route, 
       # begins with 'admin_', then we load controllers from
       # the admin sub-directory in the controllers directory.
       # Else we load controllers the normal way from 'controllers_dir'.
       
       $path = option('controllers_dir'); 
       if(strpos($callback, "admin_") === 0) $path = file_path($path, 'admin'); 
       require_once_dir($path); 
    }

### Url rewriting ###

Since version 0.4.1, Limonade supports url rewriting.

If you use Apache, with a `.htaccess` in your app folder

    <IfModule mod_rewrite.c>
      Options +FollowSymlinks
      Options +Indexes
      RewriteEngine on
      
      # if your app is in a subfolder
      # RewriteBase /my_app/ 

      # test string is a valid files
      RewriteCond %{SCRIPT_FILENAME} !-f
      # test string is a valid directory
      RewriteCond %{SCRIPT_FILENAME} !-d

      RewriteRule ^(.*)$   index.php?uri=/$1    [NC,L,QSA]
      # with QSA flag (query string append),
      # forces the rewrite engine to append a query string part of the
      # substitution string to the existing string, instead of replacing it.
    </IfModule>
    
If you use Nginx, add the following to your server declaration

    server {
        location / {
            
            try_files $uri $uri/ @rewrite;
        }
        location @rewrite {
            rewrite ^/(.*)$ /index.php?u=$1&$args;
        }
    }

then remember to set explicitly the `option('base_uri')` in your configure() function:

    option('base_uri', '/my_app'); # '/' or same as the RewriteBase in your .htaccess

You can access your site with urls like `http://your.new-website.com/my/limonade/path` instead of `http://your.new-website.com/?/my/limonade/path`.


## Views and templates ##

Template files are located by default in `views/` folder.
Views folder location can be set with the `views_dir` option.

    option('views_dir', dirname(__FILE__).'/other/dir/for/views');

To pass variables to templates, we use the function `set ()`

    set('name', 'John Doe');
    render('index.html.php');
    
Variables may also be passed directly:

    render('index.html.php', null, array('name' => 'John Doe' ));
    


`set_or_default` function allows passing a variable, and if it's empty, a default value. It is really useful for the assignment of optional parameters extracted from the url using the `params()` function.

    dispatch('/hello/:name', 'hello');
        function  hello()
        {
            # matching /hello/
            set_or_default('name', params('name'),'John');
            return render('Hello %s!'); // returns 'Hello John!' because params('name') was empty. Else it would have returned params('name') value.
        }
    
As you can notice, final output is returned by your controller. So remember to explicitly return your view in your controller with the `return` keyword! *(This remark will be particularly helpful for rubyists ;-) )*
    
    

### Layouts ###

Templates may be rendered inside another template: a layout.

Layout may be set with the `layout` function:

    layout('default_layout.php');

or directly with the template rendering function    

    render('index.html.php', 'default_layout.php');


If layout value is `null`, rendering will be done without any layout.

    render('index.html.php', null);

### Formatted strings and inline templates ###

Formatted string can be used like with  [`sprintf`](http://php.net/manual/function.sprintf.php):

    set('num', 5);
    set('where', 'tree');
    return render('There are %d monkeys in the %s') // returns 'There are 5 monkeys in the tree'

It's also possible to provide a function name as a template. By this way, for example, we can produce a single file application.

    function html_message($vars){ extract($vars);?>
        <h1>Title: <?php echo h($title); ?></h1>
        <p>Message:<br>
           <?php echo h($msg); ?></p>
    <?}
    
    // in a request handling function
    set('title', 'Hello!');
    set('msg', 'There are 100 monkeys in the Chennai and bangalore');
    return render('html_message');

### HTML Templates ###

`html` function is used in the same way as `render`.
A header specifies the proper HTTP `Content-type` (`text/html`) and encoding setting defined through options (utf8 by default).

    html('my_template.html.php');

### Templates XML ###

`xml` function is used in the same way as `render`.
A header specifies the proper HTTP `Content-type` (`text/xml`) and encoding setting defined through options (utf8 by default).

    xml('my_template.xml.php');

### Templates CSS ###

`css` function is used in the same way as `render`.
A header specifies the proper HTTP `Content-type` (`text/css`) and encoding setting defined through options (utf8 by default).

    css('screen.css.php');

### Templates JS ###

`js` function is used in the same way as `render`.
A header specifies the proper HTTP `Content-type` (`application/javascript`) and encoding setting defined through options (utf8 by default).

    js('app.js.php');

### Templates TXT ###

`txt` function is used in the same way as `render`.
A header specifies the proper HTTP `Content-type` (`text/plain`) and encoding setting defined through options (utf8 by default).

    txt('index.txt.php');
    
### Templates JSON ###

`json` is used the same way as 
 [`json_encode`](http://php.net/manual/function.json-encode.php) function, and returns a string containing the JSON representation of a value.
A header specifies the proper HTTP `Content-type` (`application/x-javascript`) and encoding setting defined through options (utf8 by default).

    json($my_data);

### Serving files ###

The `render_file` function can render a file directly to the ouptut buffer.
    
    render_file(option('public_dir').'foo.jpg');

A header specifies the proper HTTP `Content-type` depending on the file extension, and for text files, encoding setting defined through options (utf8 by default) .

Output is temporized so that it can easily handle large files.

### Partials ###

The `partial` function is a shortcut to render with no layout. Useful for managing reusable blocks and keeping them in separate files.

This code

    partial('my_posts.php', array('posts'=>$posts));
    
is the same as

    render('my_posts.php', null, array('posts'=>$posts));

### Captures ###

The `content_for` function allows you to capture a block of text in a view. Then the captured block will be available for the layout. This is useful for management of layout regions like a sidebar or to set javascript or stylesheet files that are specific to a view.


For example with this layout:

    <div id="content">
      <div id="main">
        <?php echo $content; ?>
      </div>
      <div id="side">
        <?php if (isset($side)) echo $side; ?>
      </div>
    </div>
    
And in your view:

    <p>My main content</p>
    
    <?php content_for('side'); ?>
    <ul>
      <li><a href="<?php echo url_for('/pages/item1')?>">Item 1</a></li>
      <li><a href="<?php echo url_for('/pages/item2')?>">Item 2</a></li>
    </ul>
    <?php end_content_for(); ?>

Rendered result is:

    <div id="content">
      <div id="main">
        <p>My main content</p>
      </div>
      <div id="side">
        <ul>
          <li><a href="?/pages/item1">Item 1</a></li>
          <li><a href="?/pages/item1">Item 2</a></li>
        </ul>
      </div>
    </div>


The above example is detailed in [this tutorial](http://blog.limonade-php.net/post/438674987/how-to-use-content-for-and-partial).

Use captures with partials, it will help you to organize your views and will keep you from having to copy/paste the same code many times.

## Hooks and filters ##

Limonade allows the user to define some functions to enhance the Limonade behaviour with its own needs.

Some of those, like the `before` hook and the `after` filter are commonly used, and others are only for advanced usage that might require a good comprehension of Limonade internals.


### Before ###

You can define a `before` function that will be executed before each request. This is very useful to define a default layout or for passing common variables to the templates.

    function before($route)
    {
        layout('default_layout.php');
        set('site_title', 'My Website');
    }


The current matching route is also passed to the before function, so you can test it. It's an array as returned by the internal `route_find` function, with these values: 

* `method` (HTTP method)
* `pattern` (regexp pattern)
* `names` (params names)
* `callback` (callback)
* `options` (route options)
* `params` (current params)

### After ###

An `after` output filter is also available. It's executed after each request and can apply a transformation to the output (except for `render_file` outputs  which are sent directly to the output buffer).

    function after($output){
      $config = array('indent' => TRUE,
                      'output-xhtml' => TRUE,
                      'wrap' => 200);
      
      $encoding = strtoupper(str_replace('-','', option('encoding')));
      $tidy = tidy_parse_string($output, $config, $encoding);
      $tidy->cleanRepair();
      return $tidy;
    }
    
The current executed route is also available for `after` function.

### Before render ###

You can define a `before_render` function that will filter your view before rendering it.

The first three parameters are the same as those passed to the `render` function:

* `$content_or_func`: the view string
* `$layout`: current layout path
* `$locals`: variables passed directly to the `render` function

Last parameter, `$view_path` is by default `file_path(option('views_dir'), $content_or_func);`

    function before_render($content_or_func, $layout, $locals, $view_path)
    {
      # Transform $content_or_func, $layout, $locals or $view_path.
      # Then return there new values
      return array($content_or_func, $layout, $locals, $view_path);
    }

### Autorender ###

You can define your own `autorender` function to make automatic rendering  depending on current matching route. It will be executed if your controller returns a null output.

    dispatch('/', 'hello');
    function hello()
    {
        # process some stuff...
        set('name', 'Bob');
        
        # but don't return anything
        # ( like if you were ending this function with return null; )
    }
    
    function autorender($route)
    {
        $view = $route['callback'] . ".html.php";
        return html($view);
    }
    
In this example, when url `/` is called, `hello()` is executed and then `autorender()` renders the matching `hello.html.php` view.

### Before exit ###

If you define a `before_exit`, it is called at the begining of the stop/exit process (`stop_and_exit` function called automatically at Limonade application termination).

    function before_exit($exit)
    {
        # $exit is the same parameter as the one passed to `stop_and_exit`.
        # If it's false, the exit process will not be executed, 
        # only the stop instructions
        # by default it is true
    }

### Before sending a header ###

You can define a `before_sending_header` function that will be called before Limonade emits a header() call. This way you can add additional headers:

    dispatch('/style.css', 'css');
    function css()
    {
        # Generate css file and output
        return css('style.css.php');
    }

    function before_sending_header($header)
    {
        if (strpos($header, 'text/css') !== false)
        {
            # intercept text/css content-type and add caching to the headers
            send_header("Cache-Control: max-age=600, public");
        }
    }

__Caution__: Take care not to cause a loop by repeatedly calling `send_header()` from the `before_sending_header()` function!


## Configuration ##

You can define a `configure` that will be executed when application is launched (at the begining of the `run` execution).
You can define options inside it, a connection to a database ...

    function configure()
    {
        $env = $_SERVER['HTTP_HOST'] == "localhost" ? ENV_DEVELOPMENT : ENV_PRODUCTION;
        option('env', $env);
        if(option('env') > ENV_PRODUCTION)
    	{
    		options('dsn', 'sqlite:db/development.db'));
    	}
    	else
    	{
    	    options('dsn', 'sqlite:db/production.db'));
    	}
        $GLOBALS['my_db_connexion'] = new PDO(option('dsn'));
    }

PHP files contained in the `option('lib_dir')` folder (`lib/` by default) are loaded with [`require_once`](http://php.net/manual/function.require-once.php) just after executing `configure`. So you can place in this folder all your PHP libraries and functions so that they will be loaded and available at application launch.

## Options ##

The `option` function allows you to define and access the options of the application.

    option('env', ENV_PRODUCTION);
    option('env'); // return ENV_PRODUCTION value
    
If the name of option is not specified, it returns an array of all the options set.

You can use it to manage Limonade options and your own custom options in your application.

Default Limonade options have the following values:

    option('root_dir',        $root_dir); // this folder contains your main application file
    option('base_path',          $base_path);
    option('base_uri',           $base_uri); // set it manually if you use url_rewriting
    option('limonade_dir',       dirname(__FILE__).'/'); // this fiolder contains the limonade.php main file
    option('limonade_views_dir', dirname(__FILE__).'/limonade/views/');
    option('limonade_public_dir',dirname(__FILE__).'/limonade/public/');
    option('public_dir',         $root_dir.'/public/');
    option('views_dir',          $root_dir.'/views/');
    option('controllers_dir',    $root_dir.'/controllers/');
    option('lib_dir',            $root_dir.'/lib/');
    option('error_views_dir',    option('limonade_views_dir'));
    option('env',                ENV_PRODUCTION);
    option('debug',              true);
    option('session',            LIM_SESSION_NAME); // true, false or the name of your session
    option('encoding',           'utf-8');
    option('x-sendfile',         0); // 0: disabled, 
                                     // X-SENDFILE: for Apache and Lighttpd v. >= 1.5,
                                     // X-LIGHTTPD-SEND-FILE: for Apache and Lighttpd v. < 1.5

## Sessions ##

Session starts automatically by default. Then you can access session variables like you used to do, with `$_SESSION` array.

You can disable sessions with the `session` option.

⌘ [see snippet example](http://gist.github.com/159327)

### Flash ###

Flash is a special use of sessions. A flash value will be available only on next request and will be deleted after. It's very useful to raise errors on a form or to notice a successful action.

* `flash($name, $value...)` defines a flash for the next request
* in views, you can get current flash values with the `$flash` array or `flash_now($name)` function.

⌘ [see snippet example](http://gist.github.com/162680)

## Helpers ##

See sources or api for more about all available helpers.

### url_for ###

You can use the `url_for` function for rendering limonade urls. They will be well formed from whatever folder in the document root your application is installed on your web server.

    # with option('base_uri', '?')
    url_for('one', 'two', 'three'); # returns ?/one/two/three
    url_for('one', 'two', array('page' => 1)); # returns ?/one/two&amp;page=2
    

If you want to use url rewriting, you need to explicitly set the `base_uri` option ( default is `/your_file_path/?`)


## Halting and error handling ##

### Halt ###

You can stop immediately the execution of the application with the `halt` function. Errors will be handled by default Limonade error handlers or those you have defined.

    halt(NOT_FOUND);
    halt("En error occured in my app...");

### Not Found ###

By default, displays the `not_found` error output function and sends a _`404 NOT FOUND`_ HTTP header.

    halt(NOT_FOUND);
    halt(NOT_FOUND, "This product doesn't exists.");
    
To define a new view for this error, you can simply declare a `not_found` function.

    function not_found($errno, $errstr, $errfile=null, $errline=null)
    {
        set('errno', $errno);
        set('errstr', $errstr);
        set('errfile', $errfile);
        set('errline', $errline);
        return html("show_not_found_errors.html.php");
    }
    
### Server Error ###

By default, displays the `server_error` error output function and sends a _`500 INTERNAL SERVER ERROR`_ HTTP header.

    halt();
    halt('Breaking bad!');
    halt(SERVER_ERROR, "Not good...");
    trigger_error("Wrong parameter", E_USER_ERROR);
    
PHP errors are also caught and sent to this error handler output.

To define a new view for this error, you can simply declare a `server_error` function.

    function server_error($errno, $errstr, $errfile=null, $errline=null)
    {
        $args = compact('errno', 'errstr', 'errfile', 'errline');	
        return html("show_server_errors.html.php", error_layout(), $args);
    }

### Error layout ###

Allows you to define and access a layout dedicated to errors.

    error_layout('error_layout.php');
    error_layout(); // return 'error_layout.php'

### Error handling ###

In addition to the common `NOT_FOUND` and `SERVER_ERROR` error displays, Limonade can redirect precise errors to your own functions.

    error(E_USER_WARNING, 'my_notices')
        function my_notices($errno, $errstr, $errfile, $errline)
        {
            // storing php warnings in a log file
            // ...
            status(SERVER_ERROR);
            return html('<h1>Server Error</h1>');
        }
        
`E_LIM_HTTP` means all HTTP errors

    error(E_LIM_HTTP, 'my_http_errors')
        function my_http_errors($errno, $errstr, $errfile, $errline)
        {
            status($errno);
            return html('<h1>'.http_response_status_code($errno).'</h1>');
        }
    
`E_LIM_PHP` means all PHP errors (sent by PHP or raised by the user through [`trigger_error`](http://php.net/manual/function.trigger-error.php) function).

## Other useful functions ##

Limonade also provides a useful set of functions that can help you managing files, HTTP… For more about those utilities, see the [source code](http://github.com/sofadesign/limonade/blob/master/lib/limonade.php) at section **7. UTILS**.

## Abstract Functions ##

/**
 * Abstract methods that might be redefined by user
 * Do not include this file in your app: it only aims to provide documentation
 * about those functions.
 * 
 * @package limonade
 * @subpackage abstract
 */
 
/**
 * It will be called when app is launched (at the begining of the run function).
 * You can define options inside it, a connection to a database ...
 *
 * @abstract this function might be redefined by user
 * @return void 
 */
function configure()
{
  return;
}

/**
 * Called in run() just after session start, and before checking request method
 * and output buffer start.  
 *
 * @abstract this function might be redefined by user
 * @return void 
 */
function initialize()
{
  return;
}

/**
 * Called in run() just after the route matching, in order to load controllers. 
 * If not specfied, the default function is called:
 * 
 * <code>
 * function autoload_controller($callback)
 * {
 *   require_once_dir(option('controllers_dir'));
 * }
 * </code>
 * 
 *
 * @param string $callback the callback defined in matching route
 * @return void
 */
function autoload_controller($callback)
{
  return;
}
 
/**
 * Called before each request.
 * This is very useful to define a default layout or passing common variables
 * to the templates.
 *
 * @abstract this function might be redefined by user
 * @param array() $route array (like returned by {@link route_build()},
 *   with keys "method", "pattern", "names", "callback", "options")
 * @return void 
 */
function before($route)
{
  
}
 
/**
 * An `after` output filter
 * 
 * Called after each request and can apply a transformation to the output
 * (except for `render_file` outputs  which are sent directly to the output buffer).
 *
 * @abstract this function might be redefined by user
 * @param string $output 
 * @param array() $route array (like returned by {@link route_find()},
 *   with keys "method", "pattern", "names", "callback", "params", "options")
 * @return string 
 */
function after($output, $route)
{
  # Call functions...
  # .. modifies $output...
  return $output;
}
 
/**
 * Not found error output
 *
 * @abstract this function might be redefined by user
 * @param string $errno 
 * @param string $errstr 
 * @param string $errfile 
 * @param string $errline 
 * @return string "not found" output string
 */
function not_found($errno, $errstr, $errfile=null, $errline=null)
{
 
}
 
/**
 * Server error output
 *
 * @abstract this function might be redefined by user
 * @param string $errno 
 * @param string $errstr 
 * @param string $errfile 
 * @param string $errline 
 * @return string "server error" output string
 */
function server_error($errno, $errstr, $errfile=null, $errline=null)
{
  
}
 
/**
 * Called when a route is not found.
 * 
 * 
 * @abstract this function might be redefined by user
 * @param string $request_method 
 * @param string $request_uri 
 * @return void 
 */
function route_missing($request_method, $request_uri)
{
  halt(NOT_FOUND, "($request_method) $request_uri"); # by default
}

/**
 * Called before stoppping and exiting application.
 *
 * @abstract this function might be redefined by user
 * @param boolean exit or not
 * @return void 
 */
function before_exit($exit)
{
  
}

/**
 * Rendering prefilter.
 * Useful if you want to transform your views before rendering.
 * The first three parameters are the same as those provided 
 * to the `render` function.
 *
 * @abstract this function might be redefined by user
 * @param string $content_or_func a function, a file in current views dir or a string
 * @param string $layout 
 * @param array $locals 
 * @param array $view_path (by default <code>file_path(option('views_dir'),$content_or_func);</code>)
 * @return array with, in order, $content_or_func, $layout, $locals vars
 *  and the calculated $view_path
 */
function before_render($content_or_func, $layout, $locals, $view_path)
{
  # transform $content_or_func, $layout, $locals or $view_path…
  return array($content_or_func, $layout, $locals, $view_path);
}


/**
 * Called only if rendering $output is_null,
 * like in a controller with no return statement.
 *
 * @abstract this function might be defined by user
 * @param array() $route array (like returned by {@link route_build()},
 *   with keys "method", "pattern", "names", "callback", "options")
 * @return string
 */
function autorender($route)
{
  # process output depending on $route
  return $output;
}

/**
 * Called if a header is about to be sent
 *
 * @abstract this function might be defined by user
 * @param string the headers that limonade will send
 * @return void
 */
function before_sending_header($header)
{

}


