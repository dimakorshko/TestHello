const signInBtn = document.querySelector('.signin-btn');
const signUpBtn = document.querySelector('.signup-btn');
const formBox = document.querySelector('.form-box');
const body = document.body;


function redirectToHomePage() {
    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;


    if (username !== "" && password !== "") {
      window.location.href = "main.html";
    }
}

signUpBtn.addEventListener('click', function(){
    formBox.classList.add('active');
    body.classList.add('active');
})

signInBtn.addEventListener('click', function(){
    formBox.classList.remove('active');
    body.classList.remove('active');
})
