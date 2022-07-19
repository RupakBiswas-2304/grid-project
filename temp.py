class Person:
  def __init__(self, fname, lname):
    self.firstname = fname
    self.lastname = lname

  def printname(self):
    print(self.firstname, self.lastname)

x = Person("John", "Doe")
x.printname()

class Student():
    def __init__(self, person):
        self.person = person
        self.grades = []
        
    def printname(self):
        return self.person.printname()

X = Student(x)
X.printname()