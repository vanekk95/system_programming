#pragma once

#ifdef HEADERDLL_EXPORTS
#define HEADERDLL_API __declspec(dllexport) 
#else
#define HEADERDLL_API __declspec(dllimport) 
#endif

namespace MathFuncs
{
	// This class is exported from the MathFuncsDll.dll
	class MyMathFuncs
	{
	public:
		// Returns a + b
		static HEADERDLL_API double Add(double a, double b);

		// Returns a - b
		static HEADERDLL_API double Subtract(double a, double b);

		// Returns a * b
		static HEADERDLL_API double Multiply(double a, double b);

		// Returns a / b
		// Throws const std::invalid_argument& if b is 0
		static HEADERDLL_API double Divide(double a, double b);
	};
}