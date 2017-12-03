(function () {
    // define url api
    var HOST = 'http://carcat.tk/api';

    // Url constructor
    var uri = function (url) {
        return HOST + url;
    };

    // define app
    var app = angular.module('app', [
        'ngRoute',
        'ngResource',
        'ngFlash',
        // 'ngCropper',
        'angularFileUpload',
        'base64'
    ]);

    var isEmail = function (email) {
        var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        return re.test(email);
    };

    // define app config
    app.config(['$routeProvider', '$locationProvider', '$resourceProvider', 'FlashProvider',
        function ($routeProvider, $locationProvider, $resourceProvider, FlashProvider) {
            $locationProvider.html5Mode(true);
            $routeProvider.when('/login', {templateUrl: '/view_users/login.html'});
            $routeProvider.when('/logout', {controller: 'LogoutController', template: ''});
            $routeProvider.when('/profile/:uid', {templateUrl: '/view_users/user-profile.html'});
            $routeProvider.when('/profile', {templateUrl: '/view_users/profile.html'});
            $routeProvider.when('/register', {templateUrl: '/view_users/register.html'});
            $routeProvider.when('/', {templateUrl: 'main.html'});
            $routeProvider.otherwise({redirectTo: '/'});
            $resourceProvider.defaults.stripTrailingSlashes = false;
            FlashProvider.setTimeout(5000);
            FlashProvider.setShowClose(true);
            FlashProvider.setOnDismiss(function () {});
        }]);

    // TODO: factory provide access to user cache
    app.factory('User', function ($cacheFactory) {
        var userCache = $cacheFactory('user');
        return userCache;
    });

    // TODO: auth
    app.factory('auth', ['$base64', '$http', function ($base64, $http) {
        return {
            query: function (url, token, success) {
                var credentials = $base64.encode(token + ':');
                return $http({
                    method: 'GET',
                    url: url,
                    headers: {'Authorization': 'Basic ' + credentials}
                }).then(success);
            }
        }
    }]);

    // TODO: run app
    app.run(function ($rootScope, $resource, $templateCache, User) {
        $rootScope.user = User;

        $rootScope.menu = [];
        if ($rootScope.menu.length < 1) {
            $rootScope.menu = $resource(uri('/categories')).query();
        }

        $templateCache.put('main.html',
            '<div ng-controller="MainController as main" class="row">\n' +
            '<flash-message></flash-message>\n' +
            '\t<div ng-repeat="item in main.items" class="col-sm-6 col-lg-4">' +
            '\t\t<span class="tumbl-image" data-image="{{item.image}}" image-bg></span>' +
            '\t\t<div class="pt-2 text-center">{{ item.title }} - {{ item.description }}</div>' +
            '\t\t<div class="pt-2">' +
            '\t\t\t<a ng-href="mailto:{{ item.author.email }}" class="mail-to"><i class="fa fa-envelope-o" aria-hidden="true"></i></a>' +
            '\t\t\t<span>{{ item.author.first_name }} {{ item.author.last_name }}</span> ' +
            '\t\t</div>' +
            '\t</div>\n' +
            '</div>');
    });

    // TODO: init facebook api
    window.fbAsyncInit = function () {

        FB.init({
            appId: document.getElementById('facebook-app-id').getAttribute('data-app-id'),
            status: true,
            autoLogAppEvents: true,
            cookie: true,
            xfbml: true,
            scope: 'publc_profile, email',
            version: 'v2.11'
        });
    };

    // TODO: upload Facebook SDK
    (function (d, s, id) {
        var js, fjs = d.getElementsByTagName(s)[0];
        if (d.getElementById(id)) {
            return;
        }
        js = d.createElement(s);
        js.id = id;
        js.src = "https://connect.facebook.net/en_US/sdk.js";
        fjs.parentNode.insertBefore(js, fjs);
    }(document, 'script', 'facebook-jssdk'));

    // TODO: upload Google client
    (function (d, s, id) {
        var js, fjs = d.getElementsByTagName(s)[0];
        if (d.getElementById(id)) {
            return;
        }
        js = d.createElement(s);
        js.id = id;
        js.src = "https://apis.google.com/js/client.js?onload=onLoadFunction";
        js.async = true;
        fjs.parentNode.insertBefore(js, fjs);
    }(document, 'script', 'google-sign-in-script'));


    // TODO: function onLoadFunction
    function onLoadFunction() {
        gapi.client.setApiKey(document.getElementById('google-app-id').getAttribute('data-key-api'));
        gapi.client.load('plus', 'v1', function () {
        })
    }

    // TODO: Main controller
    app.controller('MainController', function ($resource, User) {
        this.items = $resource(uri('/')).query();
    });

    // TODO: Login controller
    app.controller('LoginController', function ($resource, $scope, $window, $http, Flash, $base64, User) {

        // init form
        var err = false;
        var form = {email: '', password: ''};
        var user = User;
        if (user.size > 0) {
            $window.location.href = '/profile';
        }

        this.FBLogin = function () {
            toggle();
            FB.login(function (response) {
                if (response.authResponse) {
                    var access_token = FB.getAuthResponse()['accessToken'];
                    FB.api('/me', function (response) {
                        var POST = $resource(uri('/oauth/facebook'));
                        var json = new POST();
                        json.data = {"access_token": access_token};

                        POST.save(json, function (data) {
                            if (data.error) {
                                toggle();
                                $scope.alert(data.error, 'danger');
                                $scope.$apply();
                            }
                            if (data) {
                                user.put("email", data.email);
                                user.put("token", data.token);
                                user.put("picture", data.picture);
                                user.put("uid", data.uid);
                                user.put("full_name", data.full_name);
                                toggle();
                                $scope.alert('Success login as ' + data.full_name, 'success');

                                var loginBox = $('#login-box');
                                loginBox.html('<a href="/profile" class="mdl-button mdl-js-button">profile</a>');

                            }
                        }, function (data) {
                            var message = 'Server error, try it later';
                            toggle();
                            if (data.error) {
                                message = data.error
                            }
                            $scope.alert(message, 'error');
                        });
                    });
                } else {
                    console.log('User cancelled login or did not fully authorize.');
                }
            });
        };

        this.GoogleLogin = function () {
            var googleMeta = document.getElementById('google-app-id');
            toggle();
            var params = {
                'clientid': googleMeta.getAttribute('data-clientid'),
                'cookiepolicy': googleMeta.getAttribute('data-cookiepolicy'),
                'redirecturi': googleMeta.getAttribute('data-redirecturi'),
                'accesstype': googleMeta.getAttribute('data-accesstype'),
                'approvalprompt': googleMeta.getAttribute('data-approvalprompt'),
                'scope': googleMeta.getAttribute('data-scope'),
                'callback': function (result) {
                    if (result['status']['signed_in']) {
                        $http({
                                method: 'POST',
                                url: uri('/oauth/google'),
                                data: result.code,
                                headers: {
                                    'Content-Type': 'application/octet-stream; charset=utf-8'
                                }
                            }
                        ).then(function (result) {

                            user.put("email", result.data.email);
                            user.put("token", result.data.token);
                            user.put("picture", result.data.picture);
                            user.put("uid", result.data.uid);
                            user.put("full_name", result.data.full_name);

                            toggle();
                            $scope.alert('Success login as ' + result.data.full_name, 'success');

                            var loginBox = $('#login-box');
                            loginBox.html('<a href="/profile" class="mdl-button mdl-js-button">profile</a>');

                        }, function (error) {
                            console.log(error);
                        });

                    }
                }
            };
            gapi.auth.signIn(params);
        };


        $scope.alert = function (message, type) {
            /**
             * Alert function - show message and error to user
             * @type {type}
             */
            var id = Flash.create(type, message, 0, {class: 'custom-class', id: 'custom-id'}, true);
        };

        var toggle = function () {
            /**
             * toggle buttons and loading line
             */
            $('#buttons').toggle();
            $('#p2').toggle();
        };

        var resetPassword = function () {
            /**
             * Reset passwords
             * @type {string}
             */
            toggle();
            form.password = '';
            $('#password').val('').attr("placeholder", "password");
        };

        var resetData = function () {
            /**
             * reset form data
             */
            toggle();
            form.email = '';
            form.password = '';
        };

        $('#sign-in').on('click', function () {

            // hide buttons
            toggle();

            // get form data
            form.email = $('#email').val();
            form.password = $('#password').val();

            // validate data
            if (!isEmail(form.email)) {
                err = true;
                resetPassword();
                $scope.alert('Invalid email', 'danger');
                $scope.$apply();
            }
            if (form.password.length < 8) {
                err = true;
                resetPassword();
                $scope.alert('To short password minimum 8 characters', 'danger');
                $scope.$apply();
            }

            // submit form data
            if (!err) {
                var credentials = $base64.encode(form.email + ':' + form.password);

                var getToken = $resource(uri('/token'), null, {
                    query: {
                        method: 'GET',
                        headers: {
                            'Authorization': 'Basic ' + credentials
                        }
                    }
                });
                getToken.get({}, function (data) {
                    if (data.token !== undefined) {
                        user.put("email", form.email);
                        user.put("credentials", credentials);
                        user.put("picture", data.picture);
                        user.put("token", data.token);
                        user.put("uid", data.uid);
                        user.put("full_name", data.full_name);
                        resetData();
                        $scope.alert('Success login as ' + data.full_name, 'success');

                        var loginBox = $('#login-box');
                        loginBox.html('<a href="/profile" class="mdl-button mdl-js-button">profile</a>');
                    } else {
                        resetPassword();
                        $scope.alert('Incorrect email or password', 'danger');
                    }
                });

            }

        });
    });

    // TODO: Register controller
    app.controller('RegisterController', function ($scope, $resource, $window, Flash, User) {

        var form = {
            email: '',
            username: '',
            first_name: '',
            last_name: '',
            password: '',
            confpassword: ''
        };

        var user = User;
        if (user.size > 0) {
            $window.location.href = '/';
        }

        $scope.alert = function (message, type) {
            /**
             * Alert function - show message and error to user
             * @type {type}
             */
            var id = Flash.create(type, message, 0, {class: 'custom-class', id: 'custom-id'}, true);
        };

        var toggle = function () {
            /**
             * Toggle button and loading line
             */
            $('#sign-up').toggle();
            $('#p2').toggle();
        };

        $('#sign-up').on('click', function () {

            // hide button
            toggle();

            // get data from form
            form.email = $('#email').val();
            form.username = $('#username').val();
            form.first_name = $('#first_name').val();
            form.last_name = $('#last_name').val();
            form.password = $('#password').val();
            form.confpassword = $('#conf-password').val();

            var RegisterController = document.querySelector('[ng-controller="RegisterController as RegisterController"]');
            var $scope = angular.element(RegisterController).scope();
            var err = false;

            var resetData = function () {
                /**
                 * reset form data
                 */
                toggle();
                form.email = '';
                form.username = '';
                form.first_name = '';
                form.last_name = '';
                form.password = '';
                form.confpassword = '';
            };

            var resetPasswords = function () {
                /**
                 * Reset passwords
                 * @type {string}
                 */
                toggle();
                form.password = '';
                form.confpassword = '';
                $('#password').val('').attr("placeholder", "password");
                $('#conf-password').val('').attr("placeholder", "confirm password");
            };


            // data validation
            if (!isEmail(form.email)) {
                err = true;
                resetPasswords();
                $scope.alert('Invalid email', 'danger');
                $scope.$apply();
            }
            if (form.username.length < 3) {
                err = true;
                resetPasswords();
                $scope.alert('Too short user name, minimum 3 characters', 'danger');
                $scope.$apply();
            }
            if (form.first_name.length < 3) {
                err = true;
                resetPasswords();
                $scope.alert('To short first name minimum 3 characters', 'danger');
                $scope.$apply();
            }
            if (form.last_name.length < 3) {
                err = true;
                resetPasswords();
                $scope.alert('To short last name minimum 3 characters', 'danger');
                $scope.$apply();
            }
            if (form.password.length < 8) {
                err = true;
                resetPasswords();
                $scope.alert('To short password minimum 8 characters', 'danger');
                $scope.$apply();
            }
            if (form.password !== form.confpassword) {
                err = true;
                resetPasswords();
                $scope.alert('Passwords don\'t match', 'danger');
                $scope.$apply();
            }

            // submit form
            if (!err) {
                var POST = $resource(uri('/users/create'));
                var json = new POST();
                json.data = form;
                POST.save(json, function (data) {
                    if (data.error) {
                        err = true;
                        resetPasswords();
                        $scope.alert(data.error, 'danger');
                        $scope.$apply();
                    }
                    if (data.message) {
                        err = false;
                        user.put("id", data.id);
                        user.put("full_name", data.full_name);
                        user.put("email", form.email);
                        user.put("password", form.password);
                        resetData();
                        $scope.alert(data.message, 'success');
                        $window.location.href = '/login';
                    }
                }, function (data) {
                    var message = 'Server error, try it later';
                    err = false;
                    resetData();
                    if (data.error) {
                        message = data.error
                    }
                    $scope.alert(message, 'error');
                });
            }

        });

    });

    // TODO: Profile controller
    app.controller('ProfileController', function ($base64, $window, FileUploader, User) {
        var user = User;
        var $scope = this;
        $scope.error = false;
        if (user.info().size < 1) {
            $window.location.href = '/';
        }

        $scope.addedPhoto = false;

        var credentials = $base64.encode(user.get("token") + ':');
        var uploader = $scope.uploader = new FileUploader({
            method: 'POST',
            url: uri('/profile/edit/photo/' + user.get("uid")),
            headers: {'Authorization': 'Basic ' + credentials}
        });

        // FILTERS

        uploader.filters.push({
            name: 'imageFilter',
            fn: function(item /*{File|FileLikeObject}*/, options) {
                var type = '|' + item.type.slice(item.type.lastIndexOf('/') + 1) + '|';
                return '|jpg|png|jpeg|bmp|gif|'.indexOf(type) !== -1;
            }
        });

        uploader.onWhenAddingFileFailed = function(item /*{File|FileLikeObject}*/, filter, options) {
            $scope.addedPhoto = false;
            console.info('onWhenAddingFileFailed', item, filter, options);
        };
        uploader.onAfterAddingFile = function(fileItem) {
            $scope.addedPhoto = true;
            console.info('onAfterAddingFile', fileItem);
        };
        uploader.onAfterAddingAll = function(addedFileItems) {
            $scope.addedPhoto = true;
            console.info('onAfterAddingAll', addedFileItems);
        };
        uploader.onBeforeUploadItem = function(item) {
            console.info('onBeforeUploadItem', item);
        };
        uploader.onProgressItem = function(fileItem, progress) {
            console.info('onProgressItem', fileItem, progress);
        };
        uploader.onProgressAll = function(progress) {
            console.info('onProgressAll', progress);
        };
        uploader.onSuccessItem = function(fileItem, response, status, headers) {
            if (status === 204) {
                console.log(response)
                // user.put("picture", response.picture);
            } else if (status === 200) {
                $scope.error = response.error;
            }
            console.info('onSuccessItem', fileItem, response, status, headers);
        };
        uploader.onErrorItem = function(fileItem, response, status, headers) {
            console.info('onErrorItem', fileItem, response, status, headers);
        };
        uploader.onCancelItem = function(fileItem, response, status, headers) {
            console.info('onCancelItem', fileItem, response, status, headers);
        };
        uploader.onCompleteItem = function(fileItem, response, status, headers) {
            console.info('onCompleteItem', fileItem, response, status, headers);
        };
        uploader.onCompleteAll = function() {
            console.info('onCompleteAll');
        };

        console.info('uploader', uploader);


    });

    // TODO: Get user profile controller
    app.controller('UserProfileController', function ($routeParams, $resource, $base64, User, auth) {
        var userData = this;
        userData.user = {};
        this.uid = $routeParams.uid;
        var success = function (data) {
            userData.user = data.data;
            console.log(userData.user);
        };
        auth.query(uri('/profile/' + this.uid), User.get('token'), success);


    });

    // TODO: Logout controller
    app.controller('LogoutController', function ($window, User) {
        User.removeAll();
        $window.location.href = '/';
    });

    // TODO: imageBg directive.
    app.directive('imageBg', function () {
        /**
         * Add background image style to element. Use attrs.image
         */
        return function (scope, element, attrs) {
            element.css({'background-image': 'url(\'' + attrs.image + '\')'});
        }
    });

    // TODO: field directive.
    app.directive('field', function () {
        /**
         * Create input element. Get type, ids and classes from attrs
         */
        return function (scope, element, attrs) {
            var div = document.createElement('div');
            var input = document.createElement('input');
            var label = document.createElement('label');
            div.className = "mdl-textfield mdl-js-textfield fix-input";
            input.className = "mdl-textfield__input";
            label.className = "mdl-textfield__label label-color";
            input.setAttribute("id", attrs.id);
            input.setAttribute("type", attrs.type);
            label.setAttribute("for", attrs.id);
            label.appendChild(document.createTextNode(attrs.labeltext));
            div.appendChild(input);
            div.appendChild(label);
            if (attrs.errortext !== undefined) {
                var span = document.createElement('span');
                span.className = "mdl-textfield__error";
                span.appendChild(document.createTextNode(attrs.errortext));
                div.appendChild(span);
            }
            componentHandler.upgradeElement(div);
            element.append(div);
        }
    });

    // TODO: Image preview
    app.directive('ngThumb', ['$window', function($window) {
        var helper = {
            support: !!($window.FileReader && $window.CanvasRenderingContext2D),
            isFile: function(item) {
                return angular.isObject(item) && item instanceof $window.File;
            },
            isImage: function(file) {
                var type =  '|' + file.type.slice(file.type.lastIndexOf('/') + 1) + '|';
                return '|jpg|png|jpeg|bmp|gif|'.indexOf(type) !== -1;
            }
        };

        return {
            restrict: 'A',
            template: '<canvas class="rounded-circle"><canvas/>',
            link: function(scope, element, attributes) {
                if (!helper.support) return;

                var params = scope.$eval(attributes.ngThumb);

                if (!helper.isFile(params.file)) return;
                if (!helper.isImage(params.file)) return;

                var canvas = element.find('canvas');
                var reader = new FileReader();

                reader.onload = onLoadFile;
                reader.readAsDataURL(params.file);

                function onLoadFile(event) {
                    var img = new Image();
                    img.onload = onLoadImage;
                    img.src = event.target.result;
                }

                function onLoadImage() {
                    var width = params.width || this.width / this.height * params.height;
                    var height = params.height || this.height / this.width * params.width;
                    canvas.attr({ width: width, height: height });
                    canvas[0].getContext('2d').drawImage(this, 0, 0, width, height);
                }
            }
        };
    }]);

})();

