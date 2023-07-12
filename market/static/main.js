const clicker = document.querySelector('#clicker');
const header = document.querySelector('#header');

clicker.onclick = () => {
const getname = prompt('What is Your Name?');
alert (`My name is ${getname}`);
header.textContent = `This is ${getname}'s Home Page`;
};