#include <bits/stdc++.h>

using namespace std;

class Field
{
private:
    int l, r, type;

public:
    Field(int l, int r, int type);
    int getL();
    int getR();
    int getType();
};

class Assertion : public Field
{
private:
    map<int, vector<string>> *constant;

public:
    Assertion(int l, int r, map<int, vector<string>> *constant);
};

class Rawdata : public Field
{
public:
    Rawdata(int l, int r);
};

class Enumeration : public Field
{
private:
    map<int, vector<string>> *constant;

public:
    Enumeration(int l, int r, map<int, vector<string>> *constant);
};

class Loopcount : public Field
{
private:
    pair<int, int> r;

public:
    Loopcount(int l, int r, int le, int ri);
};

class Offset : public Field
{
private:
    int v;

public:
    Offset(int l, int r, int v);
};

class Size : public Field
{
private:
    int v;

public:
    Size(int l, int r, int v);
};