# File: section5_challenges/02_grade_calculator.py
# Grade calculator with weighted assignments

print("Enter your scores (0-100):")
homework = float(input("Homework score: "))
midterm = float(input("Midterm exam score: "))
final_exam = float(input("Final exam score: "))

# Grade weights
homework_weight = 0.3  # 30%
midterm_weight = 0.3   # 30%
final_weight = 0.4     # 40%

# Calculate final percentage
final_percentage = ((homework * homework_weight) +
                   (midterm * midterm_weight) +
                   (final_exam * final_weight))

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