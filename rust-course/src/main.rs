fn main() {
    println!("=== Rust İnitialized Examples ===");

    variables_and_constants();
    arithmetic_examples();
    if_else_example(17);
    loop_examples();
    function_examples();
    tuple_and_array_examples();
}

fn variables_and_constants() {
    println!("\n1) Degiskenler ve Sabitler");

    let age = 30;
    let mut points = 0;
    points += 10;

    const PI: f32 = 3.14159;

    println!("Age: {}", age);
    println!("No: {}", points);
    println!("PI: {}", PI);
}

fn arithmetic_examples() {
    println!("\n2) Arithmethic Operations ");

    let a = 12;
    let b = 5;

    println!("{} + {} = {}", a, b, a + b);
    println!("{} - {} = {}", a, b, a - b);
    println!("{} * {} = {}", a, b, a * b);
    println!("{} / {} = {}", a, b, a / b);
    println!("{} % {} = {}", a, b, a % b);
}

fn if_else_example(age: u8) {
    println!("\n3) If / Else");

    if age >= 18 {
        println!("{} yas: Resitsin.", age);
    } else {
        println!("{} yas: Resit degilsin.", age);
    }
}

fn loop_examples() {
    println!("\n4) Donguler");

    println!("for dongusu:");
    for i in 1..=5 {
        println!("Sayi: {}", i);
    }

    println!("while dongusu:");
    let mut count = 3;
    while count > 0 {
        println!("Geri sayim: {}", count);
        count -= 1;
    }
    println!("Basla!");
}
// Function Examples
fn function_examples() {
    println!("\n5) Function");

    let n = 6;
    println!("{} square = {}", n, square(n));

    let total = sum(4, 9);
    println!("4 + 9 = {}", total);
}

fn square(x: i32) -> i32 {
    x * x
}

fn sum(a: i32, b: i32) -> i32 {
    a + b
}
// Tuple and Array Examples
fn tuple_and_array_examples() {
    println!("\n6) Tuple and Array");

    let user = ("Johnny", 25, true);
    println!("Isim: {}, Yas: {}, Active: {}", user.0, user.1, user.2);

    let numbers = [10, 20, 30, 40, 50];
    println!("Array Element:");
    for (index, value) in numbers.iter().enumerate() {
        println!("index {} => {}", index, value);
    }
}
