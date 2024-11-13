#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: alex
"""

import os
import random

def clean_directory(directory_path):
    for filename in os.listdir(directory_path):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory_path, filename)
            os.remove(file_path)
            print(f"Deleted file: {file_path}")

def create_random_file(file_path):
    with open(file_path, 'w') as file:
        random_digits = ''.join([str(random.randint(0, 9)) for _ in range(15)])
        file.write(random_digits)
        print(f"Created file: {file_path} with content: {random_digits}")
