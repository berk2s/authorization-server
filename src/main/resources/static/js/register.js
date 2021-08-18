window.onload = function () {
    var warningIcon = "<svg style=\"width:24px;height:24px\" viewBox=\"0 0 24 24\">\n                <path fill=\"currentColor\" d=\"M11,15H13V17H11V15M11,7H13V13H11V7M12,2C6.47,2 2,6.5 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20Z\" />\n            </svg>";
    var tickIcon = "<svg style=\"width:24px;height:24px\" viewBox=\"0 0 24 24\">\n    <path fill=\"currentColor\" d=\"M21,7L9,19L3.5,13.5L4.91,12.09L9,16.17L19.59,5.59L21,7Z\" />\n</svg>";
    var loadingSpinner = '<div class="lds-ring"><div></div><div></div><div></div><div></div></div>';

    document.getElementById("signInBtn").addEventListener("click", function () {
        var password = document.getElementById("password").value;
        var passwordConfirm = document.getElementById("passwordConfirm").value;
        var phoneNumber = document.getElementById("phoneNumber").value;
        var email = document.getElementById("email").value;
        var firstName = document.getElementById("firstName").value;
        var lastName = document.getElementById("lastName").value;

        if (
        password.trim() == '' ||
        passwordConfirm.trim() == '' ||
        phoneNumber.trim() == '' ||
        email.trim() == '' ||
        firstName.trim() == '' ||
        lastName.trim() == '') {
            showAlert('warning-box', 'Warning', 'Username or password shouldn\'t be empty.');
        }
        else {

            if(password.trim() != passwordConfirm.trim()) {
                  showAlert('warning-box', 'Warning', 'Passwords are not matching.');
            } else {
                document.getElementById("signInBtn").innerHTML = loadingSpinner;
                            fetch("/register", {
                                method: "POST",
                                headers: {
                                    "Content-Type": "application/json"
                                },
                                body: JSON.stringify({
                                    'password': password,
                                    'phoneNumber': phoneNumber,
                                    'email': email,
                                    'firstName': firstName,
                                    'lastName': lastName
                                })
                            })
                            .then(res => {
                                return {response: res.json(), status: res.status}
                            })
                            .then(res => {

                                if(res.status != 201) {
                                    res.response.then(msg => {
                                        showAlert('error-box', 'Error', msg.error_description);
                                    })
                                } else {
                                     showAlert('succesful-box', 'Successful', 'Your account is sucessfully created, redirecting.');
                                }
                                document.getElementById("signInBtn").innerHTML = "Sign Up";
                            })
                            .catch(err => {
                            console.log(err);
                                showAlert('error-box', 'Error', 'Something went wrong, try again!');
                            document.getElementById("signInBtn").innerHTML = "Sign Up";
                            })
            }


        }



    });
    var showAlert = function (alertClass, title, description) {
        var alertBox = document.getElementById("alertbox");
        var alertIcon = document.getElementById("alertIcon");
        var alertTitle = document.getElementById("alertTitle");
        var alertDesc = document.getElementById("alertDesc");
        if (alertClass === 'warning-box') {
            alertIcon.innerHTML = warningIcon;
        }
        if (alertClass === 'succesful-box') {
            alertIcon.innerHTML = tickIcon;
        }
        if (alertClass === 'error-box') {
            alertIcon.innerHTML = warningIcon;
        }
        alertBox.classList.remove("hide-alert");
        alertBox.classList.add("show-alert");
        alertBox.classList.remove("warning-box");
        alertBox.classList.remove("succesful-box");
        alertBox.classList.remove("error-box");
        alertBox.classList.add(alertClass);
        alertTitle.innerHTML = "" + title;
        alertDesc.innerHTML = "" + description;
        setTimeout(function () {
            alertBox.classList.remove("show-alert");
            alertBox.classList.add("hide-alert");
        }, 5000);
    };
};
