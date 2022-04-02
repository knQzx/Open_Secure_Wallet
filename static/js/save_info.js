const inputSelector = document.querySelector('.form-control');
inputSelector.addEventListener('input', (event) => {
    let secretWords = document.getElementById('words_user').value;
    let hash = document.getElementById('hash').value;
    let key = document.getElementById('key').value;
    let password_start = document.getElementsByName('password_user')[0].ariaLabel;
    console.log(event);
    console.log(password_start);
    console.log(secretWords);
    console.log(hash);
    console.log(key);
    httpRequest = new XMLHttpRequest();
    XMLHttpRequest.onreadystatechange = function() {
        console.log(XMLHttpRequest.responseText);
    }
    //    httpRequest.overrideMimeType('text/xml');
    //    httpRequest.open('GET', `${window.location.origin}/update_password/${password_start}/${secretWords}/${key}/${event.target.value}`, true);
    //    httpRequest.send(null);
    // reload page
    console.log(event.target.value);
    if ((event.target.value).length >= 8) {
        location = `${window.location.origin}/update_password/${password_start}/${secretWords}/${key}/${event.target.value}`;
    } else {
        location = `${window.location.origin}/personal_account`
    }
});