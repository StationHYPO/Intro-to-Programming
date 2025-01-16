# Python Fundamentals: Practice Exercises

Welcome to your Python practice exercises! Each section builds upon the concepts we've learned, helping you develop your programming skills step by step. Remember, learning to program is like learning a musical instrument - regular practice is key to improvement.

## Section 1: Getting Started with Print Statements

Let's begin with some simple exercises using the print function. These will help you get comfortable with basic Python syntax and string manipulation.

### Exercise 1.1: Hello, You!
Write a program that prints your name and something interesting about yourself.

Example solution:
```python
# This program introduces me to the world
print("Hello, I'm Maria!")
print("I love solving puzzles and drinking coffee.")
```

### Exercise 1.2: ASCII Art
Create a simple picture using text characters. This will help you understand how print statements work with multiple lines.

Example solution:
```python
# Creating a simple house using ASCII characters
print("    /\\")
print("   /  \\")
print("  /____\\")
print("  |    |")
print("  |____|")
```

## Section 2: Working with Variables

These exercises will help you understand how to store and manipulate different types of data using variables.

### Exercise 2.1: Personal Details
Create variables to store your name, age, and favorite number. Then print them in a formatted way.

Example solution:
```python
# Storing personal information in variables
name = "Alex"
age = 25
favorite_number = 7

# Printing the information using f-strings
print(f"My name is {name}")
print(f"I am {age} years old")
print(f"My favorite number is {favorite_number}")
```

### Exercise 2.2: Temperature Converter
Create a program that converts a temperature from Celsius to Fahrenheit. Store the Celsius temperature in a variable.

Example solution:
```python
# Converting Celsius to Fahrenheit
celsius = 21
fahrenheit = (celsius * 9/5) + 32

print(f"{celsius}°C is equal to {fahrenheit}°F")
```

## Section 3: Basic Mathematics

Practice using Python's mathematical operators to solve simple problems.

### Exercise 3.1: Rectangle Calculator
Write a program that calculates the area and perimeter of a rectangle using variables for length and width.

Example solution:
```python
# Calculating rectangle measurements
length = 5
width = 3

area = length * width
perimeter = 2 * (length + width)

print(f"Rectangle dimensions: {length} x {width}")
print(f"Area: {area} square units")
print(f"Perimeter: {perimeter} units")
```

### Exercise 3.2: Shopping Calculator
Create a program that calculates the total cost of items in a shopping cart, including a sales tax.

Example solution:
```python
# Shopping cart calculator
item1_price = 14.99
item2_price = 29.99
tax_rate = 0.08  # 8% sales tax

subtotal = item1_price + item2_price
tax_amount = subtotal * tax_rate
total = subtotal + tax_amount

print(f"Subtotal: ${subtotal:.2f}")
print(f"Tax: ${tax_amount:.2f}")
print(f"Total: ${total:.2f}")
```

## Section 4: User Input

Now let's practice getting input from users and working with that input.

### Exercise 4.1: Personal Greeter
Create a program that asks for the user's name and favorite color, then creates a personalized greeting.

Example solution:
```python
# Getting user input and creating a personalized greeting
name = input("What's your name? ")
favorite_color = input("What's your favorite color? ")

print(f"Nice to meet you, {name}!")
print(f"{favorite_color} is a great color choice!")
```

### Exercise 4.2: Age Calculator
Write a program that asks for the user's birth year and calculates their approximate age.

Example solution:
```python
# Calculating age from birth year
current_year = 2024
birth_year = int(input("What year were you born? "))

age = current_year - birth_year

print(f"You are approximately {age} years old.")
```

## Section 5: Challenge Exercises

These exercises combine multiple concepts we've learned. They're more challenging, but don't worry - you have all the tools to solve them!

### Exercise 5.1: Trip Calculator
Create a program that helps plan a road trip by calculating:
- Total distance in both kilometers and miles
- Estimated fuel cost
- Travel time at different speeds

Example solution:
```python
# Road trip calculator
distance_km = float(input("Enter trip distance in kilometers: "))
fuel_efficiency = float(input("Enter your car's fuel efficiency (L/100km): "))
fuel_price = float(input("Enter fuel price per liter: "))

# Calculations
distance_miles = distance_km * 0.621371
fuel_needed = (distance_km / 100) * fuel_efficiency
total_fuel_cost = fuel_needed * fuel_price

# Travel time calculations
speed_city = 50  # km/h
speed_highway = 100  # km/h

time_city = distance_km / speed_city
time_highway = distance_km / speed_highway

print("\n=== Trip Summary ===")
print(f"Distance: {distance_km:.1f} km ({distance_miles:.1f} miles)")
print(f"Estimated fuel needed: {fuel_needed:.1f} L")
print(f"Estimated fuel cost: ${total_fuel_cost:.2f}")
print(f"Estimated time at city speeds: {time_city:.1f} hours")
print(f"Estimated time at highway speeds: {time_highway:.1f} hours")
```

### Exercise 5.2: Grade Calculator
Create a program that calculates a student's final grade based on:
- Multiple assignment scores
- Weighted percentages for each assignment
- Final percentage and letter grade

Example solution:
```python
# Grade calculator
print("Enter your scores (0-100):")
homework = float(input("Homework score: "))
midterm = float(input("Midterm exam score: "))
final_exam = float(input("Final exam score: "))

# Grade weights
homework_weight = 0.3  # 30%
midterm_weight = 0.3   # 30%
final_weight = 0.4     # 40%

# Calculate final percentage
final_percentage = (homework * homework_weight +
                   midterm * midterm_weight +
                   final_exam * final_weight)

# Determine letter grade
if final_percentage >= 90:
    letter_grade = "A"
elif final_percentage >= 80:
    letter_grade = "B"
elif final_percentage >= 70:
    letter_grade = "C"
elif final_percentage >= 60:
    letter_grade = "D"
else:
    letter_grade = "F"

print("\n=== Grade Report ===")
print(f"Homework (30%): {homework:.1f}")
print(f"Midterm (30%): {midterm:.1f}")
print(f"Final Exam (40%): {final_exam:.1f}")
print(f"Final Percentage: {final_percentage:.1f}%")
print(f"Letter Grade: {letter_grade}")
```

## Practice Tips

As you work through these exercises, remember:
1. Try to solve each exercise yourself before looking at the solution
2. Experiment with modifying the solutions to do different things
3. Pay attention to proper indentation and syntax
4. Use meaningful variable names that describe what they contain
5. Test your programs with different inputs to make sure they work correctly

If you get stuck:
- Read the error message carefully - it often tells you exactly what's wrong
- Break the problem down into smaller parts
- Try explaining the problem out loud (this really helps!)
- Check your syntax, especially looking for missing colons, quotes, or parentheses

Remember, making mistakes is a normal and valuable part of learning to program. Each error you encounter and fix helps you become a better programmer!
