#This file will use a collection of things that I have learned and put it all together...
#...with no apparent pathway or end goal at all.  In fact, if it makes sense, then I
#didn't accomplish my mission.

name = input("Enter your name. ")
print(" ")

age = input(f"Hello, {name}!  How old are you? ")
print(" ")

vehicle = input(f"{name}, tell me what make and model vehicle you drive.  For example, a Jeep Wrangler. ")
print(" ")

mpg = float(input(f"What kind of mileage (MPG) do you get in your {vehicle}, {name}? "))
print(" ")

place = input(f"If you can think of one place you like to drive to in your {vehicle}, what comes to mind? ")
print(" ")

distance = float(input(f"How far (in miles) is {place}? "))
print(" ")

gas_price = float(input(f"What is the average gas price in your area, {name}? $"))
print(" ")

mph = float(input(f"How fast do you drive to {place} in your {vehicle}, {name}? MPH: "))

gallons = distance / mpg
cost = gallons * gas_price
time = distance / mph

print(f"That means that it will take about {gallons:.2f} gallons of gasoline to drive to {place} and it will take you approximately {time:.2f} hours. It will cost you approximately ${cost:.2f}.  That isn't too much money, {name}? ")