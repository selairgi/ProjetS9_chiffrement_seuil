#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: alex
"""

def display_memory_usage():
    import tracemalloc
    current, peak = tracemalloc.get_traced_memory()
    print(f"\nConsommation actuelle de RAM: {current / 1024:.2f} KB")
    print(f"Consommation maximale de RAM pendant l'opération: {peak / 1024:.2f} KB")
