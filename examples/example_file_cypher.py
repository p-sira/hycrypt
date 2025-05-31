# hycrypt is licensed under The 3-Clause BSD License, see LICENSE.
# Copyright 2024 Sira Pornsiriprasert <code@psira.me>

from hycrypt.file_cryptosystem import FileCipher


class Person:
    def __init__(self, name: str, age: int) -> None:
        self.name = name
        self.age = age


class MyApp:
    def __init__(self, file, password) -> None:
        self.cipher = FileCipher(file)

        import os.path

        if os.path.isfile(file):
            self.data = self.parse_data(self.cipher.read(password).decode())
        else:
            self.cipher.create(password)
            self.data = []

    @staticmethod
    def parse_data(data: str) -> list[Person]:
        if not len(data):
            return []

        persons = []
        for r in data.split("\n"):
            person_data = r.split(",")
            persons.append(Person(person_data[0], int(person_data[1])))
        return persons

    @staticmethod
    def data_to_str(data: list[Person]) -> str:
        return "\n".join([f"{person.name},{person.age}" for person in data])

    def save(self):
        self.cipher.write(self.data_to_str(self.data).encode())

    def welcome(self):
        [
            print(
                f"Hello, {person.name}. "
                + ("Have a beer!" if person.age >= 20 else "Have some soda!")
            )
            for person in self.data
        ]


if __name__ == "__main__":
    app = MyApp(
        "examples/example_data", b"123456"
    )  # Password is used once and is not stored in memory.
    app.welcome()

    # May be you want to store data later and called save without prompting the user for password again.
    app.data = [
        Person("Jane", 22),
        Person("Andrew", 19),
        Person("Grandma", 72),
        Person("Jodio", 15),
    ]
    app.save()  # No password needed!

    app.welcome()
