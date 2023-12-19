#include <bits/stdc++.h>

using namespace std;

class Field
{
private:
    int l, r, type;

public:
    Field(int l, int r, int type)
    {
        this->l = l;
        this->r = r;
        this->type = type;
    };
};

class Assertion : public Field
{
private:
    map<int, vector<char *>> *constant;

public:
    Assertion(int l, int r, int type, map<int, vector<char *>> *constant) : Field(l, r, type)
    {
        constant = constant;
    }
};

class Enumeration : public Field
{
private:
    map<int, vector<char *>> *constant;

public:
    Enumeration(int l, int r, int type, map<int, vector<char *>> *constant) : Field(l, r, type)
    {
        constant = constant;
    }
};

class Loopcount : public Field
{
private:
    pair<int, int> r;

public:
    Loopcount(int l, int r, int type, int le, int ri) : Field(l, r, type)
    {
        this->r = {le, ri};
    }
};

class Offset : public Field
{
private:
    int v;

public:
    Offset(int l, int r, int type, int v) : Field(l, r, type)
    {
        this->v = v;
    }
};

class Size : public Field
{
private:
    int v;

public:
    Size(int l, int r, int type, int v) : Field(l, r, type)
    {
        this->v = v;
    }
};