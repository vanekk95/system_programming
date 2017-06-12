#include "MathFunc.h"
#include "for_main.h"
#include <stdexcept>

using namespace std;

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(NULL, TEXT("DLL_PROCESS_ATTACH"), TEXT("Hello!"), MB_OK | MB_SYSTEMMODAL);
		//patchImpotTable();
		break;
	case DLL_THREAD_ATTACH:
		MessageBox(NULL, TEXT("DLL_THREAD_ATTACH"), TEXT("Hello!"), MB_OK | MB_SYSTEMMODAL);
		break;
	case DLL_THREAD_DETACH:
		MessageBox(NULL, TEXT("DLL_THREAD_DETACH"), TEXT("Hello!"), MB_OK | MB_SYSTEMMODAL);
		break;
	case DLL_PROCESS_DETACH:
		MessageBox(NULL, TEXT("DLL_PROCESS_DETACH"), TEXT("Hello!"), MB_OK | MB_SYSTEMMODAL);
		break;
	}
	return TRUE;
}

namespace MathFuncs {

	double MyMathFuncs::Add(double a, double b) {
		return a + b;
	}

	double MyMathFuncs::Subtract(double a, double b) {
		return a - b;
	}

	double MyMathFuncs::Multiply(double a, double b) {
		return a * b;
	}

	double MyMathFuncs::Divide(double a, double b) {
		if (b == 0) {
			throw invalid_argument("b cannot be zero!");
		}
		return a / b;
	}
}