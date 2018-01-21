(function () {
  // define url api
  var HOST = '/api';

  // Url constructor
  var uri = function (url) {
    return HOST + url;
  };

  // define app
  var app = angular.module('app', [
    'ngRoute',
    'ngResource',
    'ngFlash',
    'angularFileUpload',
    'base64'
  ]);

  var isEmail = function (email) {
    /**
     * Email validation
     * @param string (email)
     * @type {RegExp}
     * @return bool
     */
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
  };

  function updateCars(auth, token) {
    /**
     * Update user cars
     */
    var $rootScope = angular.element(document.querySelector('[ng-app="app"]')).scope();
      auth.query(uri('/profile/items'), token, function (res) {
        $rootScope.myCars = res.data
      });
    }

  // define app config
  app.config(['$routeProvider', '$locationProvider', '$resourceProvider', 'FlashProvider',
    function ($routeProvider, $locationProvider, $resourceProvider, FlashProvider) {
      $locationProvider.html5Mode(true);
      $routeProvider.when('/login', {templateUrl: '/view_users/login.html'});
      $routeProvider.when('/logout', {controller: 'LogoutController', template: ''});
      $routeProvider.when('/car/:item_id', {templateUrl: '/cat_view/item.html'});
      $routeProvider.when('/brand/:brand_id', {templateUrl: '/cat_view/brand.html'});
      $routeProvider.when('/profile/edit/user', {templateUrl: '/view_users/edit_profile.html'});
      $routeProvider.when('/profile/edit/car/:item_id', {templateUrl: '/view_users/edit_item.html'});
      $routeProvider.when('/profile/delete/car/:item_id', {templateUrl: '/view_users/delete_item.html'});
      $routeProvider.when('/profile/:uid', {templateUrl: '/view_users/user-profile.html'});
      $routeProvider.when('/profile', {templateUrl: '/view_users/profile.html'});
      $routeProvider.when('/register', {templateUrl: '/view_users/register.html'});
      $routeProvider.when('/', {templateUrl: 'main.html'});
      $routeProvider.otherwise({redirectTo: '/'});
      $resourceProvider.defaults.stripTrailingSlashes = false;
      FlashProvider.setTimeout(600);
      FlashProvider.setShowClose(true);
      FlashProvider.setOnDismiss(function () {
      });
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
        var credentials = '';
        if (token.indexOf(':') > -1) {
          credentials = $base64.encode(token)
        } else {
          credentials = $base64.encode(token + ':');
        }

        return $http({
          method: 'GET',
          url: url,
          headers: {'Authorization': 'Basic ' + credentials}
        }).then(success);
      }
    }
  }]);

  // TODO: authPOST
  app.factory('authPOST', ['$base64', '$http', function ($base64, $http) {
    return {
      query: function (url, data, token, success) {
        var credentials = $base64.encode(token + ':');
        return $http({
          method: 'POST',
          url: url,
          data: data,
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
      '\t<div ng-repeat="item in main.items" class="col-sm-6 col-lg-4 mb-5">' +
      '\t\t<span class="tumbl-image" data-ng-click="main.showDescription()" ' +
      '       image-bg="{{item.images[0].url}}">' +
      '\t\t\t<div class="hide description">{{ item.description }}</div>' +
      '\t\t</span>' +
      '\t\t<div class="pt-2 text-center" id="title-link">' +
      '\t\t\t<a href="/car/{{item.id}}">{{ item.title }}</a>' +
      '\t\t</div>' +
      '\t\t<div class="pt-2">' +
      '\t\t\t<span data-ng-click="main.sendEmail(item.author.email)" class="mail-to">' +
      '\t\t\t\t<i class="fa fa-envelope-o" aria-hidden="true"></i>' +
      '\t\t\t</span>' +
      '\t\t\t<a href="/profile/{{ item.author.id }}">{{ item.author.first_name }} {{ item.author.last_name }}</a> ' +
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
  app.controller('MainController', function ($resource, $window, User) {
    var $scope = this;
    $scope.items = $resource(uri('/')).query();
    $scope.showDescription = function () {
      $('.description').toggle();
    };

    $scope.sendEmail = function (email) {
      $window.location.href = 'mailto:' + email;
    };
  });

  // TODO: Brand controller
  app.controller('BrandController', function ($resource, $routeParams, $window) {
    var $scope = this;
    $scope.items = $resource(uri('/category/' + $routeParams.brand_id)).query();
    $scope.showDescription = function () {
      $('.description').toggle();
    };

    $scope.sendEmail = function (email) {
      $window.location.href = 'mailto:' + email;
    };
  });

  // TODO: Item controller
  app.controller('ItemController', function ($resource, $routeParams, $window) {
    var $scope = this;
    $scope.car = {};
    $scope.currentImg = {};
    $resource(uri('/item/' + $routeParams.item_id)).get(
      function (data) {
        $scope.car = data;
        $scope.currentImg = $scope.car.images[0];
      }
    );

    $scope.sendEmail = function (email) {
      $window.location.href = 'mailto:' + email;
    };

    $scope.chooseImg = function (image) {
      $('#main-image').attr("src", image.url);
      $scope.currentImg = image;
    };

  });

  // TODO: Login controller
  app.controller('LoginController', function ($resource, $scope, $location, $http, auth, Flash, $base64, User) {

    // init form
    var err = false;
    var form = {email: '', password: ''};
    var user = User;
    if (user.size > 0) {
      $location.url('/profile');
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
                user.put("status", data.status);
                toggle();
                $scope.alert('Success login as ' + data.full_name, 'success');
                $location.url('/profile');
                var loginBox = $('#login-box');
                loginBox.html('<a href="/profile" class="mdl-button mdl-js-button">go to profile?</a>');

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
              user.put("status", result.data.status);
              user.put("full_name", result.data.full_name);

              toggle();
              $location.url('/profile');
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
      var id = Flash.create(type, message, 0, {
        class: 'custom-class',
        id: 'custom-id'
      }, true);
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
        var credentials = form.email + ':' + form.password;
        auth.query(uri('/token'), credentials, function (res) {

          if (res.data.token !== undefined) {
            user.put("email", res.data.email);
            user.put("picture", res.data.picture);
            user.put("token", res.data.token);
            user.put("status", res.data.status);
            user.put("first_name", res.data.first_name);
            user.put("last_name", res.data.last_name);
            user.put("username", res.data.username);
            user.put("uid", res.data.uid);
            user.put("full_name", res.data.full_name);
            resetData();
            $scope.alert('Success login as ' + res.data.full_name, 'success');
            $location.url('/profile');
            var loginBox = $('#login-box');
            loginBox.html('<a href="/profile" ' +
              'class="mdl-button mdl-js-button">go to profile?</a>');
          } else {
            resetPassword();
            $scope.alert('Incorrect email or password', 'danger');
          }
        });

      }

    });
  });

  // TODO: Register controller
  app.controller('RegisterController', function ($scope, $resource, $location, Flash, User) {

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
      $location.url('/');
    }

    $scope.alert = function (message, type) {
      /**
       * Alert function - show message and error to user
       * @type {type}
       */
      var id = Flash.create(type, message, 0, {
        class: 'custom-class',
        id: 'custom-id'
      }, true);
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
            user.put("status", "user");
            resetData();
            $scope.alert(data.message, 'success');
            $location.url('/login');
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
  app.controller('ProfileController', function ($base64, $location, FileUploader, auth, authPOST, User) {
    var user = User;
    var $scope = this;
    var $rootScope = angular.element(document.querySelector('[ng-app="app"]')).scope();

    // Check user is logged in
    if (user.info().size < 1) {
      $location.url('/');
    }

    // Define scope
    $scope.error = false;
    $scope.admin = false;
    $scope.category = false;
    $scope.brands = $rootScope.menu;
    $scope.car = {};
    $scope.addedPhoto = false;

    var toggle = function () {
      /**
       * toggle forms add car and add images
       */
      $('#add-car').toggle();
      $('#add-item-images').toggle();
    };

    if ($rootScope.myCars === undefined) updateCars(auth, User.get("token"));

    // Define admin status
    if (user.get("status") === "admin") $scope.admin = true;

    var credentials = $base64.encode(user.get("token") + ':');
    var uploader = $scope.uploader = new FileUploader({
      method: 'POST',
      url: uri('/profile/edit/photo/' + user.get("uid")),
      headers: {'Authorization': 'Basic ' + credentials},
      autoUpload: true
    });

    // filters
    uploader.filters.push({
      name: 'imageFilter',
      fn: function (item /*{File|FileLikeObject}*/, options) {
        var type = '|' + item.type.slice(item.type.lastIndexOf('/') + 1) + '|';
        return '|jpg|png|jpeg|bmp|gif|'.indexOf(type) !== -1;
      }
    });

    uploader.onWhenAddingFileFailed = function (item /*{File|FileLikeObject}*/, filter, options) {
      $scope.addedPhoto = false;
      $scope.error = "Error file format";
    };
    uploader.onAfterAddingFile = function (fileItem) {
      $scope.addedPhoto = true;
    };
    uploader.onSuccessItem = function (fileItem, response, status, headers) {
      if (response.error) {
        $scope.error = response.error;
      } else {
        user.put("picture", response.picture);
        $scope.addedPhoto = false;
      }
    };
    uploader.onErrorItem = function (fileItem, response, status, headers) {
      $scope.error = "Error upload a photo";
    };


    $scope.addCategory = function () {
      $scope.category = $('#category');
      console.log($scope.category.val());
      if ($scope.category.val() && $scope.category.val().length > 2) {
        $scope.error = false;
        var data = {"name": $scope.category.val()};
        authPOST.query(uri('/category/new'), data, user.get("token"),
          function (menu) {

            if (menu.data.error === undefined) {
              $scope.error = false;
              $rootScope.menu = menu.data;
              $scope.category.val('');
            } else {
              $scope.error = menu.data.error;
            }
          });
      } else {
        $scope.error = "too short name of category minimum 3 characters";
      }
    };


    $scope.addCar = function (car) {
      var match = false;
      for (var i = 0; i < $scope.brands.length; i++) {
        if (Number($scope.brands[i].id) === Number(car.brand)) match = true;
      }

      if (match) {
        $scope.error = false;
        if (car.title.length < 5) {
          $scope.error = 'Title has to be more when 5 characters';
        }
        if (car.description.length < 5) {
          $scope.error = 'Description has to be more when 5 characters';
        }
        if (car.model.length < 2) {
          $scope.error = 'Model has to be more when 2 characters';
        }
        if (!$scope.error) {
          car.brand = Number(car.brand);
          authPOST.query(uri('/create/item'), car, user.get('token'), function (res) {
            if (res.status === 200) {
              $scope.error = false;
              console.info('res.data', res);
              updateCars(auth, User.get("token"));
              $location.url('/profile/edit/car/' + res.data.id)

            } else {
              if (res.data.error) {
                $scope.error = res.data.error
              }
              else {
                $scope.error = "error upload images"
              }
            }
            console.info('res', res);
          });
        }
      } else {
        $scope.error = "Unknown " + car.brand + " brand";
      }

      console.info('car', car);
    }
  });

  // TODO: Profile edit controller
  app.controller('ProfileEditController', function ($base64, $location, FileUploader, auth, authPOST, User) {
    var $scope = this;

    var $rootScope = angular.element(document.querySelector('[ng-app="app"]')).scope();

    // Check user is logged in
    if (User.info().size < 1) {
      $location.url('/');
    }

    // Define scope
    $scope.error = false;
    $scope.message = false;
    $scope.admin = false;
    $scope.category = false;
    $scope.brands = $rootScope.menu;
    $scope.car = {};
    $scope.addedPhoto = false;
    $scope.user = {};
    $scope.user.uid = User.get('uid');
    $scope.user.first_name = User.get('first_name');
    $scope.user.last_name = User.get('last_name');
    $scope.user.full_name = $scope.user.first_name + ' ' + $scope.user.last_name;
    $scope.user.email = User.get('email');
    $scope.user.status = User.get('status');
    $scope.user.username = User.get('username');


    // Define admin status
    if (User.get("status") === "admin") $scope.admin = true;

    var credentials = $base64.encode(User.get("token") + ':');
    var uploader = $scope.uploader = new FileUploader({
      method: 'POST',
      url: uri('/profile/edit/photo/' + User.get("uid")),
      headers: {'Authorization': 'Basic ' + credentials},
      autoUpload: true
    });

    // filters
    uploader.filters.push({
      name: 'imageFilter',
      fn: function (item /*{File|FileLikeObject}*/, options) {
        var type = '|' + item.type.slice(item.type.lastIndexOf('/') + 1) + '|';
        return '|jpg|png|jpeg|bmp|gif|'.indexOf(type) !== -1;
      }
    });

    uploader.onWhenAddingFileFailed = function (item /*{File|FileLikeObject}*/, filter, options) {
      $scope.addedPhoto = false;
      $scope.error = "Error file format";
    };
    uploader.onAfterAddingFile = function (fileItem) {
      $scope.addedPhoto = true;
    };
    uploader.onSuccessItem = function (fileItem, response, status, headers) {
      if (response.error) {
        $scope.error = response.error;
      } else {
        User.put("picture", response.picture);
        $scope.addedPhoto = false;
      }
    };
    uploader.onErrorItem = function (fileItem, response, status, headers) {
      $scope.error = "Error upload a photo";
    };

    function checkUser(user) {
      if (user.first_name.length < 2) $scope.error = "too short first name min 2 characters";
      if (user.last_name.length < 2) $scope.error = "too short last name min 2 characters";
      if (user.username.length < 5) $scope.error = "too short username name min 5 characters";
      if (user.email.length < 7) $scope.error = "too short email min 7 characters";
      if (user.email.length > 40) $scope.error = "too large email max 40 characters";
      if (!isEmail(user.email)) $scope.error = "invalid email";
    }

    $scope.saveUser = function (user) {
      $scope.error = false;
      $scope.message = false;
      checkUser(user);
      if (!$scope.error) {
        authPOST.query(uri('/profile/edit/' + user.uid), user, User.get("token"), function (res) {
          if (res.data.message !== undefined) $scope.message = res.data.message;
          if (res.data.error !== undefined) $scope.error = res.data.error;
        });
      }
    };

  });

  // TODO: Item edit controller
  app.controller('ItemEditController', function ($base64, $location, $routeParams, FileUploader, auth, authPOST, User) {
    var user = User;
    var $scope = this;
    var $rootScope = angular.element(document.querySelector('[ng-app="app"]')).scope();

    // Check user is logged in
    if (user.info().size < 1) {
      $location.url('/');
    }

    function getCar(carId) {
      for (var i = 0; i < $rootScope.myCars.length; i++) {
        if ($rootScope.myCars[i].id === Number(carId)) {
          return $rootScope.myCars[i];
        }
      }
    }

    function setCar(car) {
      for (var i = 0; i < $rootScope.myCars.length; i++) {
        if ($rootScope.myCars[i].id === Number(car.id)) {
          $rootScope.myCars[i] = car;
        }
      }
    }


    // Define scope
    $scope.error = false;
    $scope.admin = false;
    $scope.category = false;
    $scope.brands = $rootScope.menu;
    $scope.car_id = $routeParams.item_id;
    $scope.car = getCar($scope.car_id);
    $scope.addedPhoto = false;
    if ($scope.car.images !== undefined && !$scope.car.images.length) $scope.currentImg = {};
    else $scope.currentImg = $scope.car.images[0];


    $scope.chooseImg = function (image) {
      $('#main-image').attr("src", image.url);
      $scope.currentImg = image;
    };

    console.info('car', $scope.car);
    var toggle = function () {
      /**
       * toggle forms add car and add images
       */
      $('#add-car').toggle();
      $('#add-item-images').toggle();
    };

    // Define admin status
    if (user.get("status") === "admin") $scope.admin = true;

    console.info('$routeParams', $routeParams);

    var credentials = $base64.encode(user.get("token") + ':');

    var carUploader = $scope.carUploader = new FileUploader({
      method: 'POST',
      url: uri('/item/add/images/' + user.get("uid") + '/' + $routeParams.item_id),
      headers: {'Authorization': 'Basic ' + credentials},
      autoUpload: true,
      queueLimit: 10
    });

    // filters
    carUploader.filters.push({
      name: 'imageFilter',
      fn: function (item /*{File|FileLikeObject}*/, options) {
        var type = '|' + item.type.slice(item.type.lastIndexOf('/') + 1) + '|';
        return '|jpg|png|jpeg|bmp|gif|'.indexOf(type) !== -1;
      }
    });

    carUploader.onWhenAddingFileFailed = function (item /*{File|FileLikeObject}*/, filter, options) {
      $scope.addedPhoto = false;
      $scope.error = "Error file format";
    };
    carUploader.onAfterAddingFile = function (fileItem) {
      $scope.addedPhoto = true;
    };
    carUploader.onSuccessItem = function (fileItem, response, status, headers) {
      if (response.error) {
        $scope.error = response.error;
      } else {
        console.info("picture", response);
        $scope.car.images = response;
        $scope.addedPhoto = false;
      }
    };

    carUploader.onErrorItem = function (fileItem, response, status, headers) {
      $scope.error = "Error upload a photo";
    };

    $scope.editCar = function (car) {
      var match = false;
      for (var i = 0; i < $scope.brands.length; i++) {
        if (Number($scope.brands[i].id) === Number(car.brand.id)) {
          match = true;
        }
      }

      if (match) {
        $scope.error = false;
        if (car.title.length < 5) {
          $scope.error = 'Title has to be more when 5 characters';
        }
        if (car.description.length < 5) {
          $scope.error = 'Description has to be more when 5 characters';
        }
        if (car.model.length < 2) {
          $scope.error = 'Model has to be more when 2 characters';
        }
        if (!$scope.error) {
          authPOST.query(uri('/update/item/' + car.id), car, user.get('token'), function (res) {
            if (res.status === 200) {
              $scope.error = false;
              console.info('res.data', res.data);

            } else {
              if (res.data.error) {
                $scope.error = res.data.error
              }
              else {
                $scope.error = "error upload images"
              }
            }
            console.info('res', res);
          });
        }
      } else {
        $scope.error = "Unknown " + car.brand + " brand";
      }

      console.info('car', car);
    }
  });

  // TODO: Delete Item controller
  app.controller('DeleteItemController', function ($base64, $location, $routeParams, authPOST, auth, User) {
    var $scope = this;
    var $rootScope = angular.element(document.querySelector('[ng-app="app"]')).scope();

    function getCar(carId) {
      for (var i = 0; i < $rootScope.myCars.length; i++) {
        if ($rootScope.myCars[i].id === Number(carId)) {
          return $rootScope.myCars[i];
        }
      }
    }


    $scope.error = false;
    $scope.car_id = $routeParams.item_id;
    $scope.car = getCar($scope.car_id);

    $scope.deleteCar = function () {
      $scope.error = false;
      var car_id = {'item_id': $scope.car_id};
      authPOST.query(
        uri('/delete/item/' + $scope.car_id),
        car_id,
        User.get('token'),
        function (res) {
        console.log(res);
        if (res.data.error !== undefined) $scope.error = res.data.error;
        else if (res.data.message !== undefined) {
          updateCars(auth, User.get("token"));
          $location.url('/profile');
        } else {
          $scope.error = "Server is not available, check you internet connection";
        }
      });
    };
  });

  // TODO: Get user profile controller
  app.controller('UserProfileController',
    function ($routeParams, $resource) {
      var $scope = this;
      $scope.user = {};
      $scope.uid = $routeParams.uid;
      $resource(uri('/profile/' + $routeParams.uid)).get(function (data) {
        console.log(data);
        $scope.user = data;
      });
      $scope.sendEmail = function (email) {
        $window.location.href = 'mailto:' + email;
      }
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
      element.css({'background-image': 'url(\'' + attrs.imageBg + '\')'});
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
      input.setAttribute("autocomplete", "off");
      if (attrs.model !== undefined) {
        input.setAttribute("ng-model", attrs.model);
      }
      if (attrs.pattern !== undefined) {
        input.setAttribute("pattern", attrs.pattern);
      }
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
  app.directive('ngThumb', ['$window', function ($window) {
    var helper = {
      support: !!($window.FileReader && $window.CanvasRenderingContext2D),
      isFile: function (item) {
        return angular.isObject(item) && item instanceof $window.File;
      },
      isImage: function (file) {
        var type = '|' + file.type.slice(file.type.lastIndexOf('/') + 1) + '|';
        return '|jpg|png|jpeg|bmp|gif|'.indexOf(type) !== -1;
      }
    };

    return {
      restrict: 'A',
      template: '<canvas class="rounded-circle"><canvas/>',
      link: function (scope, element, attributes) {
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
          canvas.attr({width: width, height: height});
          canvas[0].getContext('2d').drawImage(this, 0, 0, width, height);
        }
      }
    };
  }]);

})();

