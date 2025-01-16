# Python Fundamentals - Module 1
## Learning Objectives
By the end of this module, students will be able to:
- Write and run basic Python programs
- Understand and use variables and basic data types
- Perform calculations and string operations
- Get input from users and display output
- Write clear, well-documented code

## Lesson 1: Introduction to Python
### Theory (30 minutes)
- What is Python?
  - Brief history and importance
  - Why Python is great for beginners
  - Real-world applications
- Setting up Python
  - Installation guide
  - Using the Python interpreter
  - Writing your first program

### Practice (30 minutes)
```python
# Your first Python program
print("Hello, World!")

# Using the Python interpreter as a calculator
2 + 3
10 / 2
3 * 4
```

### Common Pitfalls
- Case sensitivity in Python
- Importance of proper indentation
- Understanding error messages

## Lesson 2: Variables and Data Types
### Theory (45 minutes)
- Understanding variables
  - Variables as containers for data
  - Naming conventions
  - Dynamic typing in Python
- Basic data types
  - Integers (int)
  - Floating-point numbers (float)
  - Strings (str)
  - Booleans (bool)

### Practice (45 minutes)
```python
# Working with variables
age = 25                    # Integer
height = 1.75              # Float
name = "Alice"             # String
is_student = True          # Boolean

# Printing variables
print(f"Name: {name}")
print(f"Age: {age}")
print(f"Height: {height} meters")
print(f"Student: {is_student}")

# Type checking
print(type(age))
print(type(height))
print(type(name))
print(type(is_student))
```

## Lesson 3: Basic Operations
### Theory (45 minutes)
- Arithmetic operators
  - Addition (+)
  - Subtraction (-)
  - Multiplication (*)
  - Division (/)
  - Integer division (//)
  - Modulus (%)
  - Exponentiation (**)
- String operations
  - Concatenation
  - Repetition
  - Basic string methods

### Practice (45 minutes)
```python
# Arithmetic operations
x = 10
y = 3

print(f"Addition: {x + y}")
print(f"Subtraction: {x - y}")
print(f"Multiplication: {x * y}")
print(f"Division: {x / y}")
print(f"Integer division: {x // y}")
print(f"Modulus: {x % y}")
print(f"Exponentiation: {x ** y}")

# String operations
first_name = "John"
last_name = "Doe"
full_name = first_name + " " + last_name
print(full_name)

# String methods
print(full_name.upper())
print(full_name.lower())
print(full_name.split())
```

## Lesson 4: Input and Output
### Theory (30 minutes)
- Getting user input
  - The input() function
  - Type conversion
- Formatting output
  - print() function options
  - f-strings
  - Format method

### Practice (30 minutes)
```python
# Getting user input
name = input("Enter your name: ")
age = int(input("Enter your age: "))  # Converting string to integer
height = float(input("Enter your height in meters: "))

# Formatting output
print(f"Hello, {name}!")
print("You are {} years old".format(age))
print("Your height is {:.2f} meters".format(height))

# Simple calculator
num1 = float(input("Enter first number: "))
num2 = float(input("Enter second number: "))
sum_result = num1 + num2
print(f"The sum of {num1} and {num2} is {sum_result}")
```

## Lesson 5: Comments and Documentation
### Theory (20 minutes)
- Types of comments
  - Single-line comments
  - Multi-line comments
- Documenting code
  - Why documentation is important
  - Best practices for commenting
  - Using docstrings

### Practice (20 minutes)
```python
# This is a single-line comment

"""
This is a multi-line comment
It can span several lines
Used for longer explanations
"""

def calculate_area(length, width):
    """
    Calculate the area of a rectangle.
    
    Args:
        length (float): The length of the rectangle
        width (float): The width of the rectangle
    
    Returns:
        float: The area of the rectangle
    """
    return length * width

# Example usage
area = calculate_area(5, 3)
print(f"The area is: {area}")
```

## Module Project: Personal Information Program
Create a program that:
1. Asks for user's personal information (name, age, height, favorite color)
2. Performs some basic calculations (e.g., birth year, height in different units)
3. Displays the information in a formatted way
4. Includes proper comments and documentation

## Assessment
- Quiz on basic concepts
- Code review of the module project
- Practical exercises combining all learned concepts

## Additional Resources
- Python documentation: docs.python.org
- Practice problems for each concept
- Common error messages and their solutions
- Supplementary reading materials
