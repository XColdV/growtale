
#include "stdafx.h"
#include <iostream>
#include <type_traits>
#include <filesystem>
#include "enet/enet.h"
#include <string>
#include <condition_variable>
#include <atomic>
#include <stdint.h>
#include <queue>
#include <memory>
#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#include <regex>
#endif
#ifdef __linux__
#include <stdio.h>
char _getch() {
	return getchar();
}
#endif
#include <vector>
#include <sstream>
#include <chrono>
#include <fstream>
#include "json.hpp"
#ifdef _WIN32
#include "bcrypt.h"
#include "crypt_blowfish/crypt_gensalt.cpp"
#include "crypt_blowfish/crypt_blowfish.h"
#include "crypt_blowfish/crypt_blowfish.cpp"
#include "crypt_blowfish/ow-crypt.cpp"
#include "bcrypt.cpp"
#else
#include "bcrypt.h"
#include "bcrypt.cpp"
#include "crypt_blowfish/crypt_gensalt.h"
#include "crypt_blowfish/crypt_gensalt.cpp"
#include "crypt_blowfish/crypt_blowfish.h"
#include "crypt_blowfish/crypt_blowfish.cpp"
#include "crypt_blowfish/ow-crypt.h"
#include "crypt_blowfish/ow-crypt.cpp"
#include "bcrypt.h"
#endif
#include <thread> // TODO
#include <mutex> // TODO
#include <regex>

#pragma warning(disable : 4996)
int totaluserids = 0;
int online = 0;
using namespace std;
using json = nlohmann::json;
vector<string> bannedlist;
bool serverIsFrozen = false;
//#define TOTAL_LOG
#define REGISTRATION
#include <signal.h>
#ifdef __linux__
#include <cstdint>
typedef unsigned char BYTE;
typedef unsigned char __int8;
typedef unsigned short __int16;
typedef unsigned int DWORD;
#endif
ENetHost* server;
int cId = 1;
BYTE* itemsDat = 0;
int itemsDatSize = 0;
BYTE* itemsDatNormal = 0;
int itemsDatSizeNormal = 0;
int itemdathashNormal;
int lastIPLogon = 0;
int configPort = 802;
string music = "";
long long int lastIPWait = 0;
int resultnbr1 = 0;
int resultnbr2 = 0;
int hasil = 0;
int prize = 0;
long long int quest = 0;
class A {};

enum E : int {};

template <class T>
T f(T i)
{
	static_assert(std::is_integral<T>::value, "Integral required.");
	return i;
}
unsigned int sleep(unsigned int seconds);
//Linux equivalent of GetLastError
#ifdef __linux__
string GetLastError() {
	return strerror(errno);
}
//Linux has no byteswap functions.
ulong _byteswap_ulong(ulong x)
{
	// swap adjacent 32-bit blocks
	//x = (x >> 32) | (x << 32);
	// swap adjacent 16-bit blocks
	x = ((x & 0xFFFF0000FFFF0000) >> 16) | ((x & 0x0000FFFF0000FFFF) << 16);
	// swap adjacent 8-bit blocks
	return ((x & 0xFF00FF00FF00FF00) >> 8) | ((x & 0x00FF00FF00FF00FF) << 8);
}
#endif

/***bcrypt***/
std::vector<std::string> split(std::string strToSplit, char delimeter)
{
	std::stringstream ss(strToSplit);
	std::string item;
	std::vector<std::string> splittedStrings;
	while (std::getline(ss, item, delimeter))
	{
		splittedStrings.push_back(item);
	}
	return splittedStrings;
}

std::vector<std::string> split(std::string stringToBeSplitted, std::string delimeter)
{
	std::vector<std::string> splittedString;
	int startIndex = 0;
	int  endIndex = 0;
	while ((endIndex = stringToBeSplitted.find(delimeter, startIndex)) < stringToBeSplitted.size())
	{

		std::string val = stringToBeSplitted.substr(startIndex, endIndex - startIndex);
		splittedString.push_back(val);
		startIndex = endIndex + delimeter.size();

	}
	if (startIndex < stringToBeSplitted.size())
	{
		std::string val = stringToBeSplitted.substr(startIndex);
		splittedString.push_back(val);
	}
	return splittedString;

}
bool verifyPassword(string password, string hash) {
	int ret;

	ret = bcrypt_checkpw(password.c_str(), hash.c_str());
	assert(ret != -1);

	return !ret;
}

string hashPassword(string password) {
	char salt[BCRYPT_HASHSIZE];
	char hash[BCRYPT_HASHSIZE];
	int ret;

	ret = bcrypt_gensalt(12, salt);
	assert(ret == 0);
	ret = bcrypt_hashpw(password.c_str(), salt, hash);
	assert(ret == 0);
	return hash;
}

const std::string currentDateTime() {
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
	// Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
	// for more information about date/time format
	strftime(buf, sizeof(buf), "%Y/%m/%d %X", &tstruct);

	return buf;
}
/***bcrypt**/
bool ValueInRange(const std::string& input, int& min, int& max);

void sendData(ENetPeer* peer, int num, char* data, int len)
{
	/* Create a reliable packet of size 7 containing "packet\0" */
	ENetPacket* packet = enet_packet_create(0,
		len + 5,
		ENET_PACKET_FLAG_RELIABLE);
	/* Extend the packet so and append the string "foo", so it now */
	/* contains "packetfoo\0"                                      */
	/* Send the packet to the peer over channel id 0. */
	/* One could also broadcast the packet by         */
	/* enet_host_broadcast (host, 0, packet);         */
	memcpy(packet->data, &num, 4);
	if (data != NULL)
	{
		memcpy(packet->data + 4, data, len);
	}
	char zero = 0;
	memcpy(packet->data + 4 + len, &zero, 1);
	enet_peer_send(peer, 0, packet);
	enet_host_flush(server);
}

int getPacketId(char* data)
{
	return *data;
}

char* getPacketData(char* data)
{
	return data + 4;
}

string text_encode(char* text)
{
	string ret = "";
	while (text[0] != 0)
	{
		switch (text[0])
		{
		case '\n':
			ret += "\\n";
			break;
		case '\t':
			ret += "\\t";
			break;
		case '\b':
			ret += "\\b";
			break;
		case '\\':
			ret += "\\\\";
			break;
		case '\r':
			ret += "\\r";
			break;
		default:
			ret += text[0];
			break;
		}
		text++;
	}
	return ret;
}

int ch2n(char x)
{
	switch (x)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'A':
		return 10;
	case 'B':
		return 11;
	case 'C':
		return 12;
	case 'D':
		return 13;
	case 'E':
		return 14;
	case 'F':
		return 15;
	default:
		break;
	}
}


char* GetTextPointerFromPacket(ENetPacket* packet)
{
	char zero = 0;
	memcpy(packet->data + packet->dataLength - 1, &zero, 1);
	return (char*)(packet->data + 4);
}

BYTE* GetStructPointerFromTankPacket(ENetPacket* packet)
{
	unsigned int packetLenght = packet->dataLength;
	BYTE* result = NULL;
	if (packetLenght >= 0x3C)
	{
		BYTE* packetData = packet->data;
		result = packetData + 4;
		if (*(BYTE*)(packetData + 16) & 8)
		{
			if (packetLenght < *(int*)(packetData + 56) + 60)
			{
				cout << "[!] Packet too small for extended packet to be valid" << endl;
				cout << "[!] Sizeof float is 4.  TankUpdatePacket size: 56" << endl;
				result = 0;
			}
		}
		else
		{
			int zero = 0;
			memcpy(packetData + 56, &zero, 4);
		}
	}
	return result;
}

int GetMessageTypeFromPacket(ENetPacket* packet)
{
	int result;

	if (packet->dataLength > 3u)
	{
		result = *(packet->data);
	}
	else
	{
		cout << "[!] Bad packet length, ignoring message" << endl;
		result = 0;
	}
	return result;
}


vector<string> explode(const string& delimiter, const string& str)
{
	vector<string> arr;

	int strleng = str.length();
	int delleng = delimiter.length();
	if (delleng == 0)
		return arr;//no change

	int i = 0;
	int k = 0;
	while (i < strleng)
	{
		int j = 0;
		while (i + j < strleng && j < delleng && str[i + j] == delimiter[j])
			j++;
		if (j == delleng)//found delimiter
		{
			arr.push_back(str.substr(k, i - k));
			i += delleng;
			k = i;
		}
		else
		{
			i++;
		}
	}
	arr.push_back(str.substr(k, i - k));
	return arr;
}

struct GamePacket
{
	BYTE* data;
	int len;
	int indexes;
};


GamePacket appendFloat(GamePacket p, float val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 1;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendFloat(GamePacket p, float val, float val2)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 8];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 3;
	memcpy(n + p.len + 2, &val, 4);
	memcpy(n + p.len + 6, &val2, 4);
	p.len = p.len + 2 + 8;
	p.indexes++;
	return p;
}

GamePacket appendFloat(GamePacket p, float val, float val2, float val3)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 12];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 4;
	memcpy(n + p.len + 2, &val, 4);
	memcpy(n + p.len + 6, &val2, 4);
	memcpy(n + p.len + 10, &val3, 4);
	p.len = p.len + 2 + 12;
	p.indexes++;
	return p;
}

GamePacket appendInt(GamePacket p, int val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 9;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendIntx(GamePacket p, int val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 5;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendString(GamePacket p, string str)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + str.length() + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 2;
	int sLen = str.length();
	memcpy(n + p.len + 2, &sLen, 4);
	memcpy(n + p.len + 6, str.c_str(), sLen);
	p.len = p.len + 2 + str.length() + 4;
	p.indexes++;
	return p;
}

GamePacket createPacket()
{
	BYTE* data = new BYTE[61];
	string asdf = "0400000001000000FFFFFFFF00000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	for (int i = 0; i < asdf.length(); i += 2)
	{
		char x = ch2n(asdf[i]);
		x = x << 4;
		x += ch2n(asdf[i + 1]);
		memcpy(data + (i / 2), &x, 1);
		if (asdf.length() > 61 * 2) throw 0;
	}
	GamePacket packet;
	packet.data = data;
	packet.len = 61;
	packet.indexes = 0;
	return packet;
}

GamePacket packetEnd(GamePacket p)
{
	BYTE* n = new BYTE[p.len + 1];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	char zero = 0;
	memcpy(p.data + p.len, &zero, 1);
	p.len += 1;
	//*(int*)(p.data + 52) = p.len;
	*(int*)(p.data + 56) = p.indexes;//p.len-60;//p.indexes;
	*(BYTE*)(p.data + 60) = p.indexes;
	//*(p.data + 57) = p.indexes;
	return p;
}
struct InventoryItem {
	__int16 itemID;
	__int16 itemCount;
};


struct PlayerInventory {
	vector<InventoryItem> items;
	//int inventorySize = 200;
};


#define cloth0 cloth_hair
#define cloth1 cloth_shirt
#define cloth2 cloth_pants
#define cloth3 cloth_feet
#define cloth4 cloth_face
#define cloth5 cloth_hand
#define cloth6 cloth_back
#define cloth7 cloth_mask
#define cloth8 cloth_necklace
#define cloth9 cloth_ances
#define STR16(x, y) (*(uint16_t*)(&(x)[(y)]))
#define STRINT(x, y) (*(int*)(&(x)[(y)]))
#define Property_Zero 0
#define Property_NoSeed 1
#define Property_Dropless 2
#define Property_Beta 4
#define Property_Mod 8
#define Property_Untradable 16
#define Property_Wrenchable 32
#define Property_MultiFacing 64
#define Property_Permanent 128
#define Property_AutoPickup 256
#define Property_WorldLock 512
#define Property_NoSelf 1024
#define Property_RandomGrow 2048
#define Property_Public 4096

vector<string>guildmem;
vector<string>guildelder;
vector<string>guildco;
struct PlayerInfo {
	// items
	vector<string> paid;
	string doorID = "";
	int wrenchedBlockLocation = -1;
	int lastdropitemcount = 0;
	int lastdropitem = 0;
	int lasttrashitem = 0;
	int lasttrashitemcount = 0;

	int blockvisual = 0;
	int droppeditemcount = 0;

	bool hasSecurity = false;
	bool online = false;
	int c0de = 0;

	int respawnX = 0;
	int respawnY = 0;

	bool ischeck = false;
	int checkx = 0;
	int checky = 0;

	int lastprice = 0;
	string seller = "";

	int userID;

	bool isNicked = false;

	vector<string>worldsowned;
	vector<string>createworldsowned;
	int wrenchsession = 0;

	int lavaLevel = 0;

	string wrenchedplayer = "";
	string wrenchdisplay = "";

	int atmgems = 0;
	int gttrwls = 0;

	int guildranklevel = 0;

	int posX;
	int posY;

	int lastPunchY;
	int lastPunchX;

	int SignPosX;
	int SignPosY;

	string macaddress = "";
	string lastInfo = "";
	string lastInfoWorld = "";
	string lastfriend = "";

	int bandate = 0;
	int bantime = 0;

	bool hasLogon = false;

	bool premiumpass = false;


	bool legend = false;
	bool milk = false;

	bool isIn = false;	
	int netID;
	bool tradeSomeone = false;
	string trdStarter = "";
	bool haveGrowId = false;
	int characterState = 0;
	vector<string>friendinfo;
	vector<string>createfriendtable;
	string tankIDName = "";
	string tankIDNamebackup = "";
	string tankIDNamebackupp = "";
	int xp = 0;
	int level = 1;
	bool isAccess = false;
	string tankIDPass = "";
	string requestedName = "";
	string rawName = "";
	string displayName = "";
	string country = "";
	int adminLevel = 0;
	string currentWorld = "EXIT";
	string lastInfoname = "";
	string lastgm = "";
	string lastgmname = "";
	string lastgmworld = "";
	string guildlast = "";
	bool isinvited = false;
	int guildBg = 0;
	int guildFg = 0;
	int petlevel = 0;
	//GUILD SYSTEM
	string guildStatement = "";
	string guildLeader = "";
	vector <string> guildmatelist;
	vector<string>guildMembers;
	int guildlevel = 0;
	int guildexp = 0;
	string createGuildName = "";
	string createGuildStatement = "";
	string createGuildFlagBg = "";
	string createGuildFlagFg = "";

	string guild = "";

	bool joinguild = false;

	//GUILD SYSTEM 
	bool radio = true;
	int peffect = 8421376;
	int wrenchx;
	int wrenchy;
	int blockx = 0;
	int blocky = 0;
	int x;
	int y;
	int xy;
	int x1;
	int y1;
	bool isRotatedLeft = false;
	bool RotatedLeft = false;
	string charIP = "";
	bool isUpdating = false;
	bool joinClothesUpdated = false;

	string RequestedName = "";
	string f = "";
	string protocol = "";
	string gameVersion = "";
	string cbits = "";
	string fz = "";
	string lmode = "";
	string playerage = "";
	string GDPR = "";
	string hash2 = "";
	string meta = "";
	string fhash = "";
	string rid = "";
	string platformid = "";
	string deviceversion = "";
	string hash = "";
	string metaip = "";
	string mac = "";
	string reconnect = "";
	string wk = "";
	string zf = "";

	// rubble
	int rubble = 0;

	// bet system
	string bettername = "";
	bool isInBet = false;
	bool isspun = false;

	// msg
	string msgName = "";
	string lastMsger = "";
	string lastMsgerTrue = "";
	string lastMsgWorld = "";

	bool taped = false;

	// trade
	bool isTrading = false;
	string tradername = "";
	int acceptedTrade = 0;
	int tradeitem1 = 0;
	int tradeitem2 = 0;
	int tradeitem3 = 0;
	int tradeitem4 = 0;

	int cloth_hair = 0; // 0
	int cloth_shirt = 0; // 1
	int cloth_pants = 0; // 2
	int cloth_feet = 0; // 3
	int cloth_face = 0; // 4
	int cloth_hand = 0; // 5
	int cloth_back = 0; // 6
	int cloth_mask = 0; // 7
	int cloth_necklace = 0; // 8
	int cloth_ances = 0; // 9

	// achievements

	int ThisLandIsMyLand = 0;
	int ban = 0;

	bool canWalkInBlocks = false; // 1
	bool canDoubleJump = false; // 2
	bool isInvisible = false; // 4
	bool noHands = false; // 8
	bool noEyes = false; // 16
	bool noBody = false; // 32
	bool devilHorns = false; // 64
	bool goldenHalo = false; // 128
	bool isFrozen = false; // 2048
	bool isCursed = false; // 4096
	bool isDuctaped = false; // 8192
	bool haveCigar = false; // 16384
	bool isShining = false; // 32768
	bool isZombie = false; // 65536
	bool isHitByLava = false; // 131072
	bool haveHauntedShadows = false; // 262144
	bool haveGeigerRadiation = false; // 524288
	bool haveReflector = false; // 1048576
	bool isEgged = false; // 2097152
	bool havePineappleFloag = false; // 4194304
	bool haveFlyingPineapple = false; // 8388608
	bool haveSuperSupporterName = false; // 16777216
	bool haveSupperPineapple = false; // 33554432
	long long int gem = 0;
	long long int wls = 0;
	bool isGhost = false;
	//bool 
	int skinColor = 0xC8E5FFFF; //normal SKin color like gt!

	bool isRespawning = false;
	long long int lastRESPAWN = 0;

	PlayerInventory inventory;
	short currentInventorySize = 0;
	bool loadedInventory = false;

	long long int lastSPIN = 0;
	long long int lastSB = 0;
	long long int lastMUTED = 0;
	long long int lastBREAK = 0;
	int mutetime = 0;
};
struct oof {
	bool magplant = true; //mag code!1!!!1!!11
	bool gazette = false;
};

int getState(PlayerInfo* info) {
	int val = 0;
	val |= info->canWalkInBlocks << 0;
	val |= info->canDoubleJump << 1;
	val |= info->noHands << 3;
	val |= info->noEyes << 4;
	val |= info->noBody << 5;
	val |= info->goldenHalo << 7;
	val |= info->isFrozen << 11;
	val |= info->isCursed << 12;
	val |= info->isDuctaped << 13;
	val |= info->haveCigar << 14;
	val |= info->isShining << 15;
	val |= info->isZombie << 16;
	val |= info->isHitByLava << 17;
	val |= info->haveHauntedShadows << 18;
	val |= info->haveGeigerRadiation << 19;
	val |= info->haveReflector << 20;
	val |= info->isEgged << 21;
	val |= info->havePineappleFloag << 22;
	val |= info->haveFlyingPineapple << 23;
	val |= info->haveSuperSupporterName << 24;
	val |= info->haveSupperPineapple << 25;
	return val;
}

int getCharstat(PlayerInfo* info) {
	int val = 0;
	if (info->haveGrowId == false) {
		val = 50000;
	}
	else {
		val = 0;
	}
	if (info->cloth_hand == 6028) val = 1024;
	if (info->cloth_hand == 6262) val = 8192;

	return val;
}
struct DroppedItem { // TODO
	int id = 0;
	int uid = -1;
	int count = 0;
	int x = -1, y = -1;
};
struct WorldItem {
	__int16 foreground = 0;
	__int16 background = 0;
	int breakLevel = 0;
	long long int breakTime = 0;
	bool isLocked = false;
	int displayblock;
	bool rotatedLeft = false;
	bool water = false;
	bool fire = false;
	bool glue = false;
	bool red = false;
	bool green = false;
	bool blue = false;

	int clothHair = 0;
	int clothHead = 0;
	int clothMask = 0;
	int clothHand = 0;
	int clothNeck = 0;
	int clothShirt = 0;
	int clothPants = 0;
	int clothFeet = 0;
	int clothBack = 0;

	int dropItem = 0;
	int amount = 0; // like this

	string text = "";

	vector<string> mailbox;

	int gravity = 0;
	bool flipped = false;
	bool active = false;
	bool silenced = false;
	int16_t lockId = 0;
	string label = "";
	string destWorld = "";
	string destId = "";
	string currId = "";
	string password = "";
	int intdata = 0;
	bool activated = false;
	int displayBlock = 0;
};
struct WorldInfo {
	int width = 100;
	int height = 60;
	string name = "TEST";
	WorldItem* items;
	string owner = "";
	int weather = 0;
	int rainitem = 0;
	int stuffgrav = 0;
	bool isPublic = false;
	bool isNuked = false;
	vector<string> acclist;
	bool noclip = false;
	int ownerID = 0;
	int stuffID = 0;
	int gravity = 0;
	vector<DroppedItem> droppedItems;
	int droppedItemUid = 0;
	bool isCasino = false;
	int droppedCount = 0;
	bool magplant = false;
	int maggems = 0;
	bool online = false;
};
WorldInfo generateWorld(string name, int width, int height)
{
	WorldInfo world;
	world.name = name;
	world.width = width;
	world.height = height;
	world.items = new WorldItem[world.width * world.height];
	int randMB = (rand() % 100);
	for (int i = 0; i < world.width * world.height; i++)
	{
		if (i >= 3700)
			world.items[i].background = 14;
		if (i >= 3700)
			world.items[i].foreground = 2;
		if (i == 3600 + randMB)
			world.items[i].foreground = 6;
		else if (i >= 3600 && i < 3700)
			world.items[i].foreground = 0;
		if (i == 3700 + randMB)
			world.items[i].foreground = 8;
		if (i >= 3800 && i < 5400 && !(rand() % 48)) { world.items[i].foreground = 10; }
		if (i >= 5000 && i < 5400 && !(rand() % 6)) { world.items[i].foreground = 4; }
		else if (i >= 5400) { world.items[i].foreground = 8; }
	}
	return world;
}
class PlayerDB {
public:
	static string getProperName(string name);
	static string fixColors(string text);
	static int playerLogin(ENetPeer* peer, string username, string password);
	static int playerRegister(ENetPeer* peer, string username, string password, string passwordverify, string email, string discord);

	static int guildRegister(ENetPeer* peer, string guildName, string guildStatement, string guildFlagfg, string guildFlagbg);
};

enum LabelStyles {
	LABEL_BIG,
	LABEL_SMALL
};

enum SpacerTypes
{
	SPACER_BIG,
	SPACER_SMALL
};

enum CheckboxTypes
{
	CHECKBOX_SELECTED,
	CHECKBOX_NOT_SELECTED
};
#pragma region Dialog stuff
/*
	Dialog api starts.
*/

class GTDialog
{
public:
	string dialogstr = "";
	void addSpacer(SpacerTypes type);
	void addLabelWithIcon(string text, int tileid, LabelStyles type);
	void addLabel(string text, int tileid, LabelStyles type);
	void addButton(string buttonname, string buttontext);
	void addCheckbox(string checkboxname, string string, CheckboxTypes type);
	void addTextBox(string str);
	void addSmallText(string str);
	void addInputBox(string name, string text, string cont, int size);
	void addQuickExit();
	void endDialog(string name, string accept, string nvm);
	void addCustom(string name);
	string finishDialog();

	operator string() {
		return this->dialogstr;
	}
};


void GTDialog::addSpacer(SpacerTypes type) {
	switch (type)
	{
	case SPACER_BIG:
		this->dialogstr.append("add_spacer|big|\n");
		break;
	case SPACER_SMALL:
		this->dialogstr.append("add_spacer|small|\n");
		break;
	default:
		break;
	}
}

void GTDialog::addLabelWithIcon(string text, int tileid, LabelStyles type) {
	switch (type)
	{
	case LABEL_BIG:
		this->dialogstr.append("add_label_with_icon|big|" + text + "|left|" + to_string(tileid) + "|\n");
		break;
	case LABEL_SMALL:
		this->dialogstr.append("add_label_with_icon|small|" + text + "|left|" + to_string(tileid) + "|\n");
		break;
	default:
		break;
	}
}

void GTDialog::addLabel(string text, int tileid, LabelStyles type) {
	switch (type)
	{
	case LABEL_BIG:
		this->dialogstr.append("add_label|big|" + text + "|left|\n");
		break;
	case LABEL_SMALL:
		this->dialogstr.append("add_label|small|" + text + "|left|\n");
		break;
	default:
		break;
	}
}

void GTDialog::addButton(string buttonname, string buttontext) {
	this->dialogstr.append("add_button|" + buttonname + "|" + buttontext + "|noflags|0|0|\n");
}
void GTDialog::addCheckbox(string checkboxname, string string, CheckboxTypes type) {
	switch (type)
	{
	case CHECKBOX_SELECTED:
		this->dialogstr.append("add_checkbox|" + checkboxname + "|" + string + "|1|\n");
		break;
	case CHECKBOX_NOT_SELECTED:
		this->dialogstr.append("add_checkbox|" + checkboxname + "|" + string + "|0|\n");
		break;
	default:
		break;
	}
}

void GTDialog::addTextBox(string str) {
	this->dialogstr.append("add_textbox|" + str + "|left|\n");
}

void GTDialog::addSmallText(string str) {
	this->dialogstr.append("add_smalltext|" + str + "|\n");
}

void GTDialog::addInputBox(string name, string text, string cont, int size) {
	this->dialogstr.append("add_text_input|" + name + "|" + text + "|" + cont + "|" + to_string(size) + "|\n");
}

void GTDialog::addQuickExit() {
	this->dialogstr.append("add_quick_exit|\n");
}

void GTDialog::endDialog(string name, string accept, string nvm) {
	this->dialogstr.append("end_dialog|" + name + "|" + nvm + "|" + accept + "|\n");
}

void GTDialog::addCustom(string name) {
	this->dialogstr.append(name + "\n");
}

string GTDialog::finishDialog() {
	return this->dialogstr;
}

namespace natives
{
	typedef int16_t             int16;
	typedef int32_t             int32;
	typedef int64_t             int64;

	typedef std::atomic_bool    flag;
}

class ThreadPool
{
public:
	struct BaseTask
	{
		virtual void runTask() = 0;
	};

	template <class T> struct Task : public BaseTask
	{
		Task(T task)
			: m_Task(task)
		{}

		virtual void runTask()
		{
			m_Task();
		}

		T m_Task;
	};

	template <class T, class P1> struct ParameteredTask : public BaseTask
	{
		ParameteredTask(T task, const P1& p1)
			: m_Task(task), m_P1(p1)
		{}

		virtual void runTask()
		{
			m_Task(m_P1);
		}

		T  m_Task;
		P1 m_P1;
	};

	typedef std::queue<BaseTask*>                       TaskQueue;
	typedef std::vector <std::shared_ptr<std::thread> > WorkerGroup;
	typedef std::mutex                                  QueueLock;
	typedef std::unique_lock<std::mutex>                QueueGuard;
	typedef std::condition_variable                     WorkerSignal;

	static void thMain(TaskQueue* queue, QueueLock* qlock, WorkerSignal* signal, natives::flag* online)
	{
		while (*online)
		{
			BaseTask* task = nullptr;

			std::shared_ptr<ThreadPool::QueueGuard> qguard(std::make_shared<ThreadPool::QueueGuard>(*qlock));

			if (!queue->empty())
			{
				task = queue->front();
				queue->pop();

				qguard.reset();
			}
			else if (*online)
			{
				signal->wait(*qguard);
			}

			if (nullptr != task)
			{
				task->runTask();
				delete task;
			}
		}
	}

	ThreadPool(natives::int32 size)
		: m_Online(true)
	{
		for (natives::int32 counter = 0; size > counter; ++counter)
		{
			m_Workers.push_back(std::make_shared<std::thread>(thMain, &m_Queue, &m_QLock, &m_Signal, &m_Online));
		}
	}

	void addThread()
	{
		m_Workers.push_back(std::make_shared<std::thread>(thMain, &m_Queue, &m_QLock, &m_Signal, &m_Online));
	}

	~ThreadPool()
	{
		m_Online = false;

		m_Signal.notify_all();

		std::for_each(m_Workers.begin(), m_Workers.end(), [](std::shared_ptr<std::thread> thread)->void {thread->join(); });
	}

	void enqueue(BaseTask* task)
	{
		QueueGuard guard(m_QLock);
		m_Queue.push(task);

		m_Signal.notify_all();
	}

	template <class T> void enqueue(T task)
	{
		QueueGuard guard(m_QLock);
		m_Queue.push(new Task<T>(task));

		m_Signal.notify_all();
	}

	template <class T, class P1> void enqueue(T task, const P1& p1)
	{
		QueueGuard guard(m_QLock);
		m_Queue.push(new ParameteredTask<T, P1>(task, p1));

		m_Signal.notify_all();
	}

	natives::int32 getQueueSize()
	{
		QueueGuard guard(m_QLock);
		natives::int32 size = m_Queue.size();

		return size;
	}

	WorkerGroup   m_Workers;
	TaskQueue     m_Queue;
	QueueLock     m_QLock;
	WorkerSignal  m_Signal;
	natives::flag m_Online;
};
int maxItems = 9439;
std::mutex m;

string PlayerDB::getProperName(string name) {
	string newS;
	for (char c : name) newS += (c >= 'A' && c <= 'Z') ? c - ('A' - 'a') : c;
	string ret;
	for (int i = 0; i < newS.length(); i++)
	{
		if (newS[i] == '`') i++; else ret += newS[i];
	}
	string ret2;
	for (char c : ret) if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) ret2 += c;
	return ret2;
}
void BlockLoginNoUrl(ENetPeer* peer, string message) {
	string text = "action|log\nmsg|" + message + "\n";
	string text3 = "action|logon_fail\n";

	BYTE* data = new BYTE[5 + text.length()];
	BYTE* data3 = new BYTE[5 + text3.length()];
	BYTE zero = 0;
	int type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);

	memcpy(data3, &type, 4);
	memcpy(data3 + 4, text3.c_str(), text3.length());
	memcpy(data3 + 4 + text3.length(), &zero, 1);

	ENetPacket* p = enet_packet_create(data,
		5 + text.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p);
	ENetPacket* p2 = enet_packet_create(data3,
		5 + text3.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p2);

	delete data;
	delete data3;


}
string PlayerDB::fixColors(string text) {
	string ret = "";
	int colorLevel = 0;
	for (int i = 0; i < text.length(); i++)
	{
		if (text[i] == '`')
		{
			ret += text[i];
			if (i + 1 < text.length())
				ret += text[i + 1];


			if (i + 1 < text.length() && text[i + 1] == '`')
			{
				colorLevel--;
			}
			else {
				colorLevel++;
			}
			i++;
		}
		else {
			ret += text[i];
		}
	}
	for (int i = 0; i < colorLevel; i++) {
		ret += "``";
	}
	for (int i = 0; i > colorLevel; i--) {
		ret += "`w";
	}
	return ret;
}

void toUpperCase(std::string& str)
{
	std::transform(str.begin(), str.end(), str.begin(), ::toupper);
}
long long GetCurrentTimeInternalSeconds()
{
	using namespace std::chrono;
	return (duration_cast<seconds>(system_clock::now().time_since_epoch())).count();
}
long long GetCurrentTimeInternals()
{
	using namespace std::chrono;
	return (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
}
long long GetCurrentTimeInternal()
{
	using namespace std::chrono;
	return (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
}
long long GetCurrentTimeInternalsSeconds()
{
	using namespace std::chrono;
	return (duration_cast<seconds>(system_clock::now().time_since_epoch())).count();
}
string BanDays(int time) {
	string x;
	int day = time / (24 * 3600);
	x.append(to_string(day));
	//n = n % (24 * 3600);
	return x;
}

string BanHours(int time) {
	string x;
	time = time % (24 * 3600);
	int hour = time / 3600;
	x.append(to_string(hour));
	//n = n % (24 * 3600);
	return x;
}
string BanSecs(int n) {
	string x;
	n %= 60;
	int seconds = n;
	x.append(to_string(seconds));
	//n = n % (24 * 3600);
	return x;
}
string BanMinutes(int n) {
	string x;
	n %= 3600;
	int minutes = n / 60;
	x.append(to_string(minutes));
	//n = n % (24 * 3600);
	return x;
}

void savejson(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
		std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");

		PlayerInfo* p5 = ((PlayerInfo*)(peer->data));

		string username = PlayerDB::getProperName(p5->rawName);



		if (ifff.fail()) {
			ifff.close();


		}
		if (ifff.is_open()) {
		}
		json j;
		ifff >> j; //load
		j["gems"] = ((PlayerInfo*)(peer->data))->gem;
		j["wls"] = ((PlayerInfo*)(peer->data))->wls;
		j["level"] = ((PlayerInfo*)(peer->data))->level;
		j["xp"] = ((PlayerInfo*)(peer->data))->xp;
		j["ban"] = ((PlayerInfo*)(peer->data))->ban;

		std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
		if (!o.is_open()) {
			cout << GetLastError() << endl;
			_getch();
		}

		o << j << std::endl;
	}
}
void sendLogonFail(ENetPeer* peer, string texts)
{
	string text = "action|log\nmsg|" + texts + "\n";
	string text3 = "action|logon_fail\n";
	BYTE* data = new BYTE[5 + text.length()];
	BYTE* data3 = new BYTE[5 + text3.length()];
	BYTE zero = 0;
	int type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);
	memcpy(data3, &type, 4);
	memcpy(data3 + 4, text3.c_str(), text3.length());
	memcpy(data3 + 4 + text3.length(), &zero, 1);

	ENetPacket* p = enet_packet_create(data,
		5 + text.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p);
	ENetPacket* p2 = enet_packet_create(data3,
		5 + text3.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p2);

	delete data;
	delete data3;
}
int getPlayersCountInServer()
{
	int count = 0;
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		count++;
	}
	return count;
}
void wrongpass(ENetPeer* peer) {
	string text = "action|log\nmsg|`o`4Unable to log on: `$That `0GrowID`$ or password doesnt look valid. Please try again!````\n";
	string text3 = "action|logon_fail\n";
	string dc = "https://discord.gg/ybg7TVH";
	string url = "action|set_url\nurl|" + dc + "\nlabel|Recover Password\n";


	BYTE* data = new BYTE[5 + text.length()];
	BYTE* data3 = new BYTE[5 + text3.length()];
	BYTE* dataurl = new BYTE[5 + url.length()];
	BYTE zero = 0;
	int type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);

	memcpy(dataurl, &type, 4);
	memcpy(dataurl + 4, url.c_str(), url.length());
	memcpy(dataurl + 4 + url.length(), &zero, 1);

	memcpy(data3, &type, 4);
	memcpy(data3 + 4, text3.c_str(), text3.length());
	memcpy(data3 + 4 + text3.length(), &zero, 1);

	ENetPacket* p = enet_packet_create(data,
		5 + text.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p);
	ENetPacket* p3 = enet_packet_create(dataurl,
		5 + url.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p3);
	ENetPacket* p2 = enet_packet_create(data3,
		5 + text3.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p2);

	delete data;
	delete dataurl;
	delete data3;


}
void sendConsoleMsg(ENetPeer* peer, string message) {
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), message));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void SendConsoleMsg(ENetPeer* peer, string message) {
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), message));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}
int PlayerDB::playerLogin(ENetPeer* peer, string username, string password) {
	string uname = username;
	if (uname.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != string::npos) {
		return -10;
	}
	string name = username;
	string bantime = "-1";
	string bandate = "-1";
	string ban;
	string dispname;
	string uidcheck;
	string receiveduserId = "";
	toUpperCase(name);
	if (name == "" || name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "COM1" || name == "COM2" || name == "COM3" || name == "COM4" || name == "COM5" || name == "COM6" || name == "COM7" || name == "COM8" || name == "COM9" || name == "LPT1" || name == "LPT2" || name == "LPT3" || name == "LPT4" || name == "LPT5" || name == "LPT6" || name == "LPT7" || name == "LPT8" || name == "LPT9") return -5;
	bool invsizeist = std::experimental::filesystem::exists("usersinventorysize/" + PlayerDB::getProperName(username) + ".txt");

	if (!invsizeist)
	{
		ofstream invof("usersinventorysize/" + PlayerDB::getProperName(username) + ".txt");
		invof << 30;
		invof.close();
	}
	std::ifstream ifsw("ipban.json");
	json jx;
	string ip = std::to_string(peer->address.host);
	if (ifsw.is_open()) {

		ifsw >> jx;
		string ipban = jx["ip"];
		if (ipban.find("|" + ip + "|") != std::string::npos) {
			sendLogonFail(peer, "`oSorry, but`w " + ((PlayerInfo*)(peer->data))->tankIDName + "`o account is `4IPBANNED`o! If you have some questions please Contact Us at Discord!");
			enet_peer_disconnect_later(peer, 0);
		}
	}
	if (configPort == 8080) {
		GamePacket p3 = packetEnd(appendInt(appendInt(appendString(appendString(createPacket(), "OnRedirectServer"), "52.168.136.31"), 17091), 1));

		//memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
		ENetPacket* packet3 = enet_packet_create(p3.data,
			p3.len,
			ENET_PACKET_FLAG_RELIABLE);

		enet_peer_send(peer, 0, packet3);
		delete p3.data;
	}
	int count = 0;
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		count++;
	}
	ofstream myfile;
	myfile.open("onlineplayer.txt");
	myfile << to_string(count);
	myfile.close();
	std::ifstream ifs("players/" + PlayerDB::getProperName(username) + ".json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		string pss = j["password"];
		string userid = j["userID"];
		int uid = atoi(userid.c_str());
		((PlayerInfo*)(peer->data))->userID = uid;
		if (verifyPassword(password, pss)) {
			ENetPeer* currentPeer;

			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				string mac = (((PlayerInfo*)(peer->data))->mac);
				if (mac.length() > 23)
				{
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Oh No! something is wrong and you will be disconnected..."));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					enet_peer_disconnect_later(peer, 0);
				}
				//mac length fix
				string ip = std::to_string(peer->address.host);
				if (ip.length() > 23)
				{
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Oh No! something is wrong and you will be disconnected..."));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					enet_peer_disconnect_later(peer, 0);
				}
				string tankid = ((PlayerInfo*)(peer->data))->tankIDName;
				if (tankid.length() > 25) {
					return -5;
				}
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (currentPeer == peer)
					continue;
				if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(username))
				{
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Someone else logged into this account!"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						delete p.data;
					}
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Someone else was logged into this account! He was kicked out now."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					//enet_host_flush(server);
					enet_peer_disconnect_later(currentPeer, 0);

				}
			}
			return 1;
		}
		else {
			return -1;
		}
	}
	else {
		return -2;
	}
}

bool isHere(ENetPeer* peer, ENetPeer* peer2)
{
	return ((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(peer2->data))->currentWorld;
}
bool checkNetIDs(ENetPeer* peer, ENetPeer* peer2)
{
	return ((PlayerInfo*)(peer->data))->netID == ((PlayerInfo*)(peer2->data))->netID;
}

bool checkNetIDs2(ENetPeer* peer, string nid)
{
	return ((PlayerInfo*)(peer->data))->netID == stoi(nid);
}
int PlayerDB::guildRegister(ENetPeer* peer, string guildName, string guildStatement, string guildFlagfg, string guildFlagbg) {
	if (guildName.find(" ") != string::npos || guildName.find(".") != string::npos || guildName.find(",") != string::npos || guildName.find("@") != string::npos || guildName.find("[") != string::npos || guildName.find("]") != string::npos || guildName.find("#") != string::npos || guildName.find("<") != string::npos || guildName.find(">") != string::npos || guildName.find(":") != string::npos || guildName.find("{") != string::npos || guildName.find("}") != string::npos || guildName.find("|") != string::npos || guildName.find("+") != string::npos || guildName.find("_") != string::npos || guildName.find("~") != string::npos || guildName.find("-") != string::npos || guildName.find("!") != string::npos || guildName.find("$") != string::npos || guildName.find("%") != string::npos || guildName.find("^") != string::npos || guildName.find("&") != string::npos || guildName.find("`") != string::npos || guildName.find("*") != string::npos || guildName.find("(") != string::npos || guildName.find(")") != string::npos || guildName.find("=") != string::npos || guildName.find("'") != string::npos || guildName.find(";") != string::npos || guildName.find("/") != string::npos) {
		return -1;
	}

	if (guildName.length() < 3) {
		return -2;
	}
	if (guildName.length() > 15) {
		return -3;
	}
	int fg;
	int bg;

	try {
		fg = stoi(guildFlagfg);
	}
	catch (std::invalid_argument& e) {
		return -6;
	}
	try {
		bg = stoi(guildFlagbg);
	}
	catch (std::invalid_argument& e) {
		return -5;
	}
	if (guildFlagbg.length() > 4) {
		return -7;
	}
	if (guildFlagfg.length() > 4) {
		return -8;
	}

	string fixedguildName = PlayerDB::getProperName(guildName);

	std::ifstream ifs("guilds/" + fixedguildName + ".json");
	if (ifs.is_open()) {
		return -4;
	}


	/*std::ofstream o("guilds/" + fixedguildName + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}

	json j;

	//  Guild Detail
	j["GuildName"] = guildName;
	j["GuildStatement"] = guildStatement;
	j["GuildWorld"] = ((PlayerInfo*)(peer->data))->currentWorld;

	//  Guild Level
	j["GuildLevel"] = 0;
	j["GuildExp"] = 0;

	// Guild Leader
	j["Leader"] = ((PlayerInfo*)(peer->data))->rawName;


	// Guild Flag
	j["foregroundflag"] = 0;
	j["backgroundflag"] = 0;


	// Role
	vector<string>guildmember;
	vector<string>guildelder;
	vector<string>guildco;

	j["CoLeader"] = guildelder;
	j["ElderLeader"] = guildco;
	j["Member"] = guildmem;

	o << j << std::endl; */
	return 1;
}

int PlayerDB::playerRegister(ENetPeer* peer, string username, string password, string passwordverify, string email, string discord) {
	if (username.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != string::npos) {
		return -10;
	}

	string name = username;
	totaluserids++;
	if (totaluserids == 1) totaluserids++;
	toUpperCase(name);
	if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "COM1" || name == "COM2" || name == "COM3" || name == "COM4" || name == "COM5" || name == "COM6" || name == "COM7" || name == "COM8" || name == "COM9" || name == "LPT1" || name == "LPT2" || name == "LPT3" || name == "LPT4" || name == "LPT5" || name == "LPT6" || name == "LPT7" || name == "LPT8" || name == "LPT9") return -1;
	if (name == "") return -1;
	username = PlayerDB::getProperName(username);
	if (discord.find("#") == std::string::npos && discord.length() != 0) return -5;
	if (email.find("@") == std::string::npos && email.length() != 0) return -4;
	if (passwordverify != password) return -3;
	if (username.length() < 3) return -2;
	std::ifstream ifs("players/" + username + ".json");
	if (ifs.is_open()) {
		return -1;
	}
	std::ofstream o("players/" + username + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}
	json j;
	j["username"] = username;
	j["password"] = hashPassword(password);
	j["email"] = email;
	j["discord"] = discord;
	j["adminLevel"] = 0;
	j["userID"] = std::to_string(totaluserids);
	j["ClothBack"] = 0;
	j["ClothHand"] = 0;
	j["ClothFace"] = 0;
	j["ClothShirt"] = 0;
	j["ClothPants"] = 0;
	j["ClothNeck"] = 0;
	j["ClothHair"] = 0;
	j["ClothFeet"] = 0;
	j["ClothMask"] = 0;
	j["ClothAnces"] = 0;
	j["gems"] = 0;
	j["wls"] = 0;
	j["isBanned"] = false;
	j["isMuted"] = false;
	j["online"] = false;
	j["level"] = 1;
	j["xp"] = 0;
	j["ban"] = 0;
	j["bandate"] = 0;
	j["bantime"] = 0;
	j["legend"] = false;
	j["milk"] = false;
	j["guild"] = "";
	j["joinguild"] = false;
	j["worldsowned"] = ((PlayerInfo*)(peer->data))->createworldsowned;
	o << j << std::endl;
	std::ofstream oo("inventory/" + username + ".json");
	if (!oo.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}

	json items;
	json jjall = json::array();


	json jj;
	jj["aposition"] = 1;
	jj["itemid"] = 18;
	jj["quantity"] = 1;
	jjall.push_back(jj);


	jj["aposition"] = 2;
	jj["itemid"] = 32;
	jj["quantity"] = 1;
	jjall.push_back(jj);

	for (int i = 2; i < 200; i++)
	{
		jj["aposition"] = i + 1;
		jj["itemid"] = 0;
		jj["quantity"] = 0;
		jjall.push_back(jj);
	}

	items["items"] = jjall;
	oo << items << std::endl;
	((PlayerInfo*)(peer->data))->userID = totaluserids;
	ofstream myfile;
	myfile.open("uids.txt");
	myfile << to_string(totaluserids);
	myfile.close();
	((PlayerInfo*)(peer->data))->userID = totaluserids;
	return 1;
}

void report(natives::int32 i)
{
	{
		std::unique_lock<std::mutex> guard(m);
	}

	std::this_thread::sleep_for(std::chrono::seconds(5));
}

struct AWorld {
	WorldInfo* ptr;
	WorldInfo info;
	int id;
};

class WorldDB {
public:
	WorldInfo get(string name);
	int getworldStatus(string name);
	AWorld get2(string name);
	void flush(WorldInfo info);
	void flush2(AWorld info);
	void save(AWorld info);
	void saveAll();
	void saveRedundant();
	vector<WorldInfo> getRandomWorlds();
	WorldDB();
private:
	vector<WorldInfo> worlds;
};

WorldDB::WorldDB() {
	// Constructor
}
void sendNotification(ENetPeer* peer, string song, string flag, string message) {
	GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), song), message), flag), 0));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}
string getStrUpper(string txt) {
	string ret;
	for (char c : txt) ret += toupper(c);
	return ret;
}

AWorld WorldDB::get2(string name) {
	if (worlds.size() > 200) {
#ifdef TOTAL_LOG
		cout << "[!] Saving redundant worlds!" << endl;
#endif
		saveRedundant();
#ifdef TOTAL_LOG
		cout << "[!] Redundant worlds are saved!" << endl;
#endif
	}
	AWorld ret;
	name = getStrUpper(name);
	if (name.length() < 1) throw 1; // too short name
	for (char c : name) {
		if ((c < 'A' || c>'Z') && (c < '0' || c>'9'))
			throw 2; // wrong name
	}
	if (name == "EXIT") {
		throw 3;
	}
	if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "COM1" || name == "COM2" || name == "COM3" || name == "COM4" || name == "COM5" || name == "COM6" || name == "COM7" || name == "COM8" || name == "COM9" || name == "LPT1" || name == "LPT2" || name == "LPT3" || name == "LPT4" || name == "LPT5" || name == "LPT6" || name == "LPT7" || name == "LPT8" || name == "LPT9") throw 3;
	for (int i = 0; i < worlds.size(); i++) {
		if (worlds.at(i).name == name)
		{
			ret.id = i;
			ret.info = worlds.at(i);
			ret.ptr = &worlds.at(i);
			return ret;
		}

	}
	std::ifstream ifs("worlds/" + name + ".json");
	if (ifs.is_open()) {

		json j;
		ifs >> j;
		WorldInfo info;
		info.name = j["name"].get<string>();
		info.width = j["width"].get<int>();
		info.height = j["height"].get<int>();
		info.weather = j["weather"].get<int>();
		for (int i = 0; i < j["access"].size(); i++) {
			info.acclist.push_back(j["access"][i]);
		}		
		info.owner = j["owner"].get<string>();
		info.ownerID = j["ownerID"].get<int>();
		info.magplant = j["magplant"].get<bool>();
		info.maggems = j["maggems"].get<int>();
		info.stuffID = j["stuff"].get<int>();
		info.gravity = j["gravity"].get<int>();
		info.isPublic = j["isPublic"].get<bool>();
		json tiles = j["tiles"];
		int square = info.width * info.height;
		info.items = new WorldItem[square];
		for (int i = 0; i < square; i++) {
			info.items[i].foreground = tiles[i]["fg"].get<int>();
			info.items[i].background = tiles[i]["bg"].get<int>();
			info.items[i].text = tiles[i]["text"].get<string>();
			info.items[i].label = tiles[i]["label"].get<string>();
			info.items[i].destWorld = tiles[i]["destWorld"].get<string>();
			info.items[i].destId = tiles[i]["destId"].get<string>();
			info.items[i].currId = tiles[i]["currId"].get<string>();
			info.items[i].password = tiles[i]["password"].get<string>();
			info.items[i].flipped = tiles[i]["flip"].get<bool>();
			info.items[i].active = tiles[i]["a"].get<bool>();
			info.items[i].intdata = tiles[i]["intdata"].get<int>();
		}
		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	else {
		WorldInfo info = generateWorld(name, 100, 60);

		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	throw 1;
}

WorldInfo WorldDB::get(string name) {

	return this->get2(name).info;
}
int WorldDB::getworldStatus(string name) {
	name = getStrUpper(name);
	//if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "COM1" || name == "COM2" || name == "COM3" || name == "COM4" || name == "COM5" || name == "COM6" || name == "COM7" || name == "COM8" || name == "COM9" || name == "LPT1" || name == "LPT2" || name == "LPT3" || name == "LPT4" || name == "LPT5" || name == "LPT6" || name == "LPT7" || name == "LPT8" || name == "LPT9") return -1;

	//if (name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != string::npos) return -1;
	if (name.length() > 24) return -1;
	/*for (int i = 0; i < worlds.size(); i++) {
		if (worlds.at(i).name == name)
		{
			return 0;
		}
	}*/
	return 0;
}

void WorldDB::flush(WorldInfo info)
{
	std::ofstream o("worlds/" + info.name + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
	}
	json j;
	j["name"] = info.name;
	j["width"] = info.width;
	j["height"] = info.height;
	j["weather"] = info.weather;
	j["isCasino"] = info.isCasino;
	j["access"] = info.acclist;
	j["owner"] = info.owner;
	j["ownerID"] = info.ownerID;
	j["magplant"] = info.magplant;
	j["maggems"] = info.maggems;
	j["stuff"] = info.stuffID;
	j["gravity"] = info.gravity;
	j["isPublic"] = info.isPublic;
	json tiles = json::array();
	int square = info.width * info.height;

	for (int i = 0; i < square; i++)
	{
		json tile;
		tile["fg"] = info.items[i].foreground;
		tile["bg"] = info.items[i].background;
		tile["text"] = info.items[i].text;
		tile["label"] = info.items[i].label;
		tile["destWorld"] = info.items[i].destWorld;
		tile["destId"] = info.items[i].destId;
		tile["currId"] = info.items[i].currId;
		tile["password"] = info.items[i].password;
		tile["a"] = info.items[i].active;
		tile["flip"] = info.items[i].flipped;
		tile["intdata"] = info.items[i].intdata;
		//tile["text"] = info.items[i].text;
		tiles.push_back(tile);
	}
	j["tiles"] = tiles;
	o << j << std::endl;
}

void WorldDB::flush2(AWorld info)
{
	this->flush(info.info);
}

void WorldDB::save(AWorld info)
{
	flush2(info);
	delete info.info.items;
	worlds.erase(worlds.begin() + info.id);
}

void WorldDB::saveAll()
{
	for (int i = 0; i < worlds.size(); i++) {
		flush(worlds.at(i));
	}
	worlds.clear();
}

vector<WorldInfo> WorldDB::getRandomWorlds() {
	vector<WorldInfo> ret;
	for (int i = 0; i < ((worlds.size() < 10) ? worlds.size() : 10); i++)
	{ // load first four worlds, it is excepted that they are special
		ret.push_back(worlds.at(i));
	}
	// and lets get up to 6 random
	if (worlds.size() > 4) {
		for (int j = 0; j < 6; j++)
		{
			bool isPossible = true;
			WorldInfo world = worlds.at(rand() % (worlds.size() - 4));
			for (int i = 0; i < ret.size(); i++)
			{
				if (world.name == ret.at(i).name || world.name == "EXIT")
				{
					isPossible = false;
				}
			}
			if (isPossible)
				ret.push_back(world);
		}
	}
	return ret;
}

void WorldDB::saveRedundant()
{
	for (int i = 4; i < worlds.size(); i++) {
		bool canBeFree = true;
		ENetPeer* currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (((PlayerInfo*)(currentPeer->data))->currentWorld == worlds.at(i).name)
				canBeFree = false;
		}
		if (canBeFree)
		{
			flush(worlds.at(i));
			delete worlds.at(i).items;
			worlds.erase(worlds.begin() + i);
			i--;
		}
	}
}

//WorldInfo world;
//vector<WorldInfo> worlds;
WorldDB worldDB;

void saveAllWorlds() // atexit hack plz fix
{
	GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"),
		"`4Global system message`o: Saving all worlds `oin `p5 `wseconds`o, you will be timed out for a short amount of time`w! `oDon't punch anything or you may get disconnected!``"));
	ENetPacket* packet0 = enet_packet_create(p0.data,
		p0.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_host_broadcast(server, 0, packet0);
	cout << "[!] Saving worlds..." << endl;
	worldDB.saveAll();
	cout << "[!] Worlds saved!" << endl;
	Sleep(1000);

	Sleep(200);
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Global system message`o: `2Saved `oall worlds``"));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_host_broadcast(server, 0, packet);
	delete p0.data;
	delete p.data;
}

WorldInfo* getPlyersWorld(ENetPeer* peer)
{
	try {
		return worldDB.get2(((PlayerInfo*)(peer->data))->currentWorld).ptr;
	}
	catch (int e) {
		return NULL;
	}
}
struct PlayerMoving {
	int packetType;
	int netID;
	float x;
	float y;
	int characterState;
	int plantingTree;
	float XSpeed;
	float YSpeed;
	int punchX;
	int punchY;
	int secondnetID;
};

struct BlockVisual {
	int packetType;
	int characterState;
	int punchX;
	int punchY;
	float x;
	float y;
	int plantingTree;
	float XSpeed;
	float YSpeed;
	int charStat;
	int blockid;
	int visual;
	int signs;
	int backgroundid;
	int displayblock;
	int time;
	int netID;
	//int bpm;
};


enum ClothTypes {
	HAIR,
	SHIRT,
	PANTS,
	FEET,
	FACE,
	HAND,
	BACK,
	MASK,
	NECKLACE,
	NONE
};

enum BlockTypes {
	FOREGROUND,
	BACKGROUND,
	CONSUMABLE,
	SEED,
	PAIN_BLOCK,
	BEDROCK,
	MAIN_DOOR,
	SIGN,
	DOOR,
	CLOTHING,
	FIST,
	WRENCH,
	CHECKPOINT,
	LOCK,
	GATEWAY,
	TREASURE,
	WEATHER,
	TRAMPOLINE,
	TOGGLE_FOREGROUND,
	SWITCH_BLOCK,
	SFX_FOREGROUND,
	RANDOM_BLOCK,
	PORTAL,
	PLATFORM,
	MAILBOX,
	MAGIC_EGG,
	GEMS,
	DEADLY,
	CHEST,
	FACTION,
	BULLETIN_BOARD,
	BOUNCY,
	ANIM_FOREGROUND,
	COMPONENT,
	UNKNOWN
};
struct ItemDefinition {
	int id;
	string name;
	int rarity;
	int breakHits;
	int growTime;
	ClothTypes clothType;
	BlockTypes blockType;
	string MultiFacing = "retarddddddd";
	string description = "This item has no description.";
	string effect = "(Mod removed)";
	string effects = "(Mod added)";
	bool puncheffectEXIST = false;
	int puncheffect;
	bool buffEXIST = false;
	string buff = "This item has no buff.";
	string equip = "This item has no equip message.";
	string unequip = "This item has no unequip message.";
	int properties;
};

struct PunchDefinition {
	int id;
	int pid;
};

vector<ItemDefinition> itemDefs;
vector<PunchDefinition> punchDefs;
ItemDefinition GetItemDef(int id)
{
	if (id < itemDefs.size() && id > -1)
		return itemDefs.at(id);
	return itemDefs.at(0);
}
ItemDefinition getItemDef(int id)
{
	if (id < itemDefs.size() && id > -1)
		return itemDefs.at(id);
	/*for (int i = 0; i < itemDefs.size(); i++)
	{
		if (id == itemDefs.at(i).id)
		{
			return itemDefs.at(i);
		}
	}*/
	throw 0;
	return itemDefs.at(0);
}

PunchDefinition getPunchDef(int id)
{
	if (id < punchDefs.size() && id > -1)
		return punchDefs.at(id);
	/*for (int i = 0; i < itemDefs.size(); i++)
	{
		if (id == itemDefs.at(i).id)
		{
			return itemDefs.at(i);
		}
	}*/
	throw 0;
	return punchDefs.at(0);
}

void craftItemDescriptions() {
	int current = -1;
	std::ifstream infile("Descriptions.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 3 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			if (atoi(ex[0].c_str()) + 1 < itemDefs.size())
			{
				itemDefs.at(atoi(ex[0].c_str())).description = ex[1];
				if (!(atoi(ex[0].c_str()) % 2))
					itemDefs.at(atoi(ex[0].c_str()) + 1).description = "This is a tree.";
			}
		}
	}
}
void craftItemText() {
	int current = -1;
	std::ifstream infile("effect.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 5 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			itemDefs.at(atoi(ex[0].c_str())).effect = ex[3] + " `$(`o" + ex[1] + " `omod removed)";
			itemDefs.at(atoi(ex[0].c_str())).effects = ex[2] + " `$(`o" + ex[1] + " `omod added)";
		}
	}
}
void loadPunchEffect()
{
	int current = -1;
	std::ifstream infile("PunchEffect.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 3 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			itemDefs.at(atoi(ex[0].c_str())).puncheffectEXIST = true;
			itemDefs.at(atoi(ex[0].c_str())).puncheffect = atoi(ex[1].c_str());
		}
	}
}

void BuildItemsDatabase()
{
	int current = -1;
	std::ifstream infile("CoreData.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 8 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			def.id = atoi(ex[0].c_str());
			def.name = ex[1];
			def.rarity = atoi(ex[2].c_str());
			vector<string> properties = explode(",", ex[3]);
			def.properties = Property_Zero;
			for (auto &prop : properties)
			{
				if (prop == "NoSeed")
					def.properties |= Property_NoSeed;
				if (prop == "Dropless")
					def.properties |= Property_Dropless;
				if (prop == "Beta")
					def.properties |= Property_Beta;
				if (prop == "Mod")
					def.properties |= Property_Mod;
				if (prop == "Untradable")
					def.properties |= Property_Untradable;
				if (prop == "Wrenchable")
					def.properties |= Property_Wrenchable;
				if (prop == "MultiFacing")
					def.properties |= Property_MultiFacing;
				if (prop == "Permanent")
					def.properties |= Property_Permanent;
				if (prop == "AutoPickup")
					def.properties |= Property_AutoPickup;
				if (prop == "WorldLock")
					def.properties |= Property_WorldLock;
				if (prop == "NoSelf")
					def.properties |= Property_NoSelf;
				if (prop == "RandomGrow")
					def.properties |= Property_RandomGrow;
				if (prop == "Public")
					def.properties |= Property_Public;
			}
			string bt = ex[4];
			if (bt == "Foreground_Block") {
				def.blockType = BlockTypes::FOREGROUND;
			}
			else if (bt == "Seed") {
				def.blockType = BlockTypes::SEED;
			}
			else if (bt == "Consummable") {
				def.blockType = BlockTypes::CONSUMABLE;
			}
			else if (bt == "Pain_Block") {
				def.blockType = BlockTypes::PAIN_BLOCK;
			}
			else if (bt == "Main_Door") {
				def.blockType = BlockTypes::MAIN_DOOR;
			}
			else if (bt == "Bedrock") {
				def.blockType = BlockTypes::BEDROCK;
			}
			else if (bt == "Door") {
				def.blockType = BlockTypes::DOOR;
			}
			else if (bt == "Fist") {
				def.blockType = BlockTypes::FIST;
			}
			else if (bt == "Sign") {
				def.blockType = BlockTypes::SIGN;
			}
			else if (bt == "Background_Block") {
				def.blockType = BlockTypes::BACKGROUND;
			}
			else if (bt == "Sheet_Music") {
				def.blockType = BlockTypes::BACKGROUND;
			}
			else if (bt == "Wrench") {
				def.blockType = BlockTypes::WRENCH;
			}
			else if (bt == "Checkpoint") {
				def.blockType = BlockTypes::CHECKPOINT;
			}
			else if (bt == "Lock") {
				def.blockType = BlockTypes::LOCK;
			}
			else if (bt == "Gateway") {
				def.blockType = BlockTypes::GATEWAY;
			}
			else if (bt == "Clothing") {
				def.blockType = BlockTypes::CLOTHING;
			}
			else if (bt == "Platform") {
				def.blockType = BlockTypes::PLATFORM;
			}
			else if (bt == "SFX_Foreground") {
				def.blockType = BlockTypes::SFX_FOREGROUND;
			}
			else if (bt == "Gems") {
				def.blockType = BlockTypes::GEMS;
			}
			else if (bt == "Toggleable_Foreground") {
				def.blockType = BlockTypes::TOGGLE_FOREGROUND;
			}
			else if (bt == "Treasure") {
				def.blockType = BlockTypes::TREASURE;
			}
			else if (bt == "Deadly_Block") {
				def.blockType = BlockTypes::DEADLY;
			}
			else if (bt == "Trampoline_Block") {
				def.blockType = BlockTypes::TRAMPOLINE;
			}
			else if (bt == "Animated_Foreground_Block") {
				def.blockType = BlockTypes::ANIM_FOREGROUND;
			}
			else if (bt == "Portal") {
				def.blockType = BlockTypes::PORTAL;
			}
			else if (bt == "Random_Block") {
				def.blockType = BlockTypes::RANDOM_BLOCK;
			}
			else if (bt == "Bouncy") {
				def.blockType = BlockTypes::BOUNCY;
			}
			else if (bt == "Chest") {
				def.blockType = BlockTypes::CHEST;
			}
			else if (bt == "Switch_Block") {
				def.blockType = BlockTypes::SWITCH_BLOCK;
			}
			else if (bt == "Magic_Egg") {
				def.blockType = BlockTypes::MAGIC_EGG;
			}
			else if (bt == "Mailbox") {
				def.blockType = BlockTypes::MAILBOX;
			}
			else if (bt == "Bulletin_Board") {
				def.blockType = BlockTypes::BULLETIN_BOARD;
			}
			else if (bt == "Faction") {
				def.blockType = BlockTypes::FACTION;
			}
			else if (bt == "Component") {
				def.blockType = BlockTypes::COMPONENT;
			}
			else if (bt == "Weather_Machine") {
				def.blockType = BlockTypes::WEATHER;
			}
			else {
				//cout << "[!] Unknown property for ID: " << def.id << " which wants property " << bt << endl;
				def.blockType = BlockTypes::UNKNOWN;
			}
			def.breakHits = atoi(ex[7].c_str());
			def.growTime = atoi(ex[8].c_str());
			string cl = ex[9];
			if (def.blockType == BlockTypes::CLOTHING)
			{
				if (cl == "None") {
					def.clothType = ClothTypes::NONE;
				}
				else if (cl == "Hat") {
					def.clothType = ClothTypes::HAIR;
				}
				else if (cl == "Shirt") {
					def.clothType = ClothTypes::SHIRT;
				}
				else if (cl == "Pants") {
					def.clothType = ClothTypes::PANTS;
				}
				else if (cl == "Feet") {
					def.clothType = ClothTypes::FEET;
				}
				else if (cl == "Face") {
					def.clothType = ClothTypes::FACE;
				}
				else if (cl == "Hand") {
					def.clothType = ClothTypes::HAND;
				}
				else if (cl == "Back") {
					def.clothType = ClothTypes::BACK;
				}
				else if (cl == "Hair") {
					def.clothType = ClothTypes::MASK;
				}
				else if (cl == "Chest") {
					def.clothType = ClothTypes::NECKLACE;
				}
				else {
					def.clothType = ClothTypes::NONE;
				}
			}
			else
			{
				def.clothType = ClothTypes::NONE;
			}

			if (++current != def.id)
			{
				cout << "[!] Critical error! Unordered database at item " << std::to_string(current) << "/" << std::to_string(def.id) << "!" << endl;
			}
			maxItems = def.id;
			itemDefs.push_back(def);
		}
	}
	craftItemDescriptions();
	craftItemText();
}


struct Admin {
	string username;
	string password;
	int level = 0;
	long long int lastSB = 0;
};

vector<Admin> admins;

void addAdmin(string username, string password, int level)
{
	Admin admin;
	admin.username = username;
	admin.password = password;
	admin.level = level;
	admins.push_back(admin);
}

int getAdminLevel(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level;
		}
	}
	return 0;
}

bool canSB(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level > 1) {
			using namespace std::chrono;
			if (admin.lastSB + 900000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() || admin.level == 999)
			{
				admins[i].lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
				return true;
			}
			else {
				return false;
			}
		}
	}
	return false;
}

bool canClear(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level > 0;
		}
	}
	return false;
}
int adminlevel(string name) {
	std::ifstream ifff("players/" + PlayerDB::getProperName(name) + ".json");
	json j;
	ifff >> j;

	int adminlevel;
	adminlevel = j["adminLevel"];

	ifff.close();
	if (adminlevel == 0) {
		return 0;
	}
	else {
		return adminlevel;
	}

}
int level(string name) {
	std::ifstream ifff("players/" + PlayerDB::getProperName(name) + ".json");
	json j;
	ifff >> j;

	int level;
	level = j["level"];

	ifff.close();
	return level;

}

string getRankText(string name) {
	int lvl = 0;
	lvl = adminlevel(name);
	if (lvl == 0) {
		return "`wTHE FALLEN";
	}
	if (lvl == 111) {
		return "`$THE RECLUSE";
	}
	else if (lvl == 444) {
		return "`#THE AMBITIOUS";
	}
	else if (lvl == 666) {
		return "`4Administrator";
	}
	else if (lvl == 777) {
		return "`4THE ROYAL GUARD";
	}
	else if (lvl == 999) {
		return "`4Server-Creator";
	}
	else if (lvl == 1337) {
		return "`cTHE JUDGE";
	}
}
string getRankId(string name) {
	int lvl = 0;
	lvl = adminlevel(name);
	if (lvl == 0) {
		return "18";
	}
	if (lvl == 111) {
		return "274";
	}
	else if (lvl == 444) {
		return "278";
	}
	else if (lvl == 666) {
		return "276";
	}
	else if (lvl == 777) {
		return "732";
	}
	else if (lvl == 999) {
		return "1956";
	}
	else if (lvl == 1337) {
		return "2376";
	}
}
string getRankTexts(string name) {
	int lvl = 0;
	lvl = level(name);
	if (lvl <= 10) {
		return "`2Newbie";
	}
	if (lvl >= 11) {
		return "`1Advance";
	}
	if (lvl >= 50) {
		return "`cPro";
	}
	if (lvl >= 100) {
		return "`eMaster";
	}
	if (lvl >= 150) {
		return "`9Expert";
	}
	if (lvl >= 200) {
		return "`5A`4C`qE";
	}
}
string getRankIds(string name) {
	int lvl = 0;
	lvl = level(name);
	if (lvl <= 10) {
		return "3900";
	}
	if (lvl >= 11) {
		return "3192";
	}
	if (lvl >= 50) {
		return "7832";
	}
	if (lvl >= 100) {
		return "7586";
	}
	if (lvl >= 150) {
		return "6312";
	}
	if (lvl >= 200) {
		return "1956";
	}
}
bool isSuperAdmin(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 999) {
			return true;
		}
	}
	return false;
}

void sendInventory(ENetPeer* peer, PlayerInventory inventory)
{
	string asdf2 = "0400000009A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000000000000000";
	int inventoryLen = inventory.items.size();
	int packetLen = (asdf2.length() / 2) + (inventoryLen * 4) + 4;
	BYTE * data2 = new BYTE[packetLen];
	for (int i = 0; i < asdf2.length(); i += 2)
	{
		char x = ch2n(asdf2[i]);
		x = x << 4;
		x += ch2n(asdf2[i + 1]);
		memcpy(data2 + (i / 2), &x, 1);
	}
	int endianInvVal = _byteswap_ulong(inventoryLen);
	memcpy(data2 + (asdf2.length() / 2) - 4, &endianInvVal, 4);
	endianInvVal = _byteswap_ulong(((PlayerInfo*)(peer->data))->currentInventorySize);
	memcpy(data2 + (asdf2.length() / 2) - 8, &endianInvVal, 4);
	int val = 0;
	for (int i = 0; i < inventoryLen; i++)
	{
		val = 0;
		val |= inventory.items.at(i).itemID;
		val |= inventory.items.at(i).itemCount << 16;
		val &= 0x00FFFFFF;
		val |= 0x00 << 24;
		memcpy(data2 + (i * 4) + (asdf2.length() / 2), &val, 4);
	}
	ENetPacket* packet3 = enet_packet_create(data2,
		packetLen,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet3);
	delete data2;
	//enet_host_flush(server);
}
void SearchInventoryItem(ENetPeer* peer, int fItemid, int fQuantity, bool& iscontains)
{
	iscontains = false;
	for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
	{
		if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == fItemid && ((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount >= fQuantity) {

			iscontains = true;
			break;
		}
	}
}
void GiveChestPrizeGems(ENetPeer* peer, int gemsAmount)
{
	((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem += gemsAmount;

	GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
	ENetPacket* packetpp = enet_packet_create(pp.data,
		pp.len,
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packetpp);
	delete pp.data;

	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `wYou have got `9" + to_string(gemsAmount) + " `wGems from Daily chest`^!"));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
	savejson(peer);
	int effect = 29;
	ENetPeer* currentPeer;

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {

			int x = ((PlayerInfo*)(peer->data))->x;
			int y = ((PlayerInfo*)(peer->data))->y;
			GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

			ENetPacket* packetd = enet_packet_create(psp.data,
				psp.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(currentPeer, 0, packetd);
			delete psp.data;
		}
	}


}
void SaveShopsItem(int fItemid, int fQuantity, ENetPeer* peer, bool& success)
{
	size_t invsizee = ((PlayerInfo*)(peer->data))->currentInventorySize;
	bool invfull = false;
	bool alreadyhave = false;


	if (((PlayerInfo*)(peer->data))->inventory.items.size() == invsizee) {


		GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`4Whoops!|left|1048|\nadd_spacer|small|\nadd_textbox|`oSoory! Your inventory is full! You can purchase an inventory upgrade in the shop.|\nadd_spacer|small|\nadd_button|close|`5Close|0|0|"));
		ENetPacket* packet = enet_packet_create(ps.data,
			ps.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete ps.data;


		alreadyhave = true;
	}

	bool iscontains = false;
	for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
	{


		if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == fItemid) {


			GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`4Whoops!|left|1048|\nadd_spacer|small|\nadd_textbox|`oSoory! Your inventory already contains this item!|\nadd_spacer|small|\nadd_button|close|`5Close|0|0|"));
			ENetPacket* packet = enet_packet_create(ps.data,
				ps.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete ps.data;


			iscontains = true;
		}
	}

	if (iscontains == true || alreadyhave == true)
	{
		success = false;
	}
	else
	{
		success = true;

		std::ifstream iffff("inventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");

		json jj;

		if (iffff.fail()) {
			iffff.close();
			cout << "[!] SaveShopsItem funkcijoje (ifstream dalyje) error: itemid - " << fItemid << ", kiekis - " << fQuantity << endl;

		}
		if (iffff.is_open()) {


		}

		iffff >> jj; //load


		std::ofstream oo("inventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
		if (!oo.is_open()) {
			cout << GetLastError() << " SaveShopsItem funkcijoje (ofstream dalyje) error: itemid - " << fItemid << ", kiekis - " << fQuantity << endl;
			_getch();
		}

		//jj["items"][aposition]["aposition"] = aposition;

		for (int i = 0; i < ((PlayerInfo*)(peer->data))->currentInventorySize; i++)
		{
			int itemid = jj["items"][i]["itemid"];
			int quantity = jj["items"][i]["quantity"];
			if (itemid == 0 && quantity == 0)
			{
				jj["items"][i]["itemid"] = fItemid;
				jj["items"][i]["quantity"] = fQuantity;
				break;
			}

		}
		oo << jj << std::endl;


		InventoryItem item;
		item.itemID = fItemid;
		item.itemCount = fQuantity;
		((PlayerInfo*)(peer->data))->inventory.items.push_back(item);

		sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
	}
}

void SaveShopsItemMoreTimes(int fItemid, int fQuantity, ENetPeer* peer, bool& success)
{
	size_t invsizee = ((PlayerInfo*)(peer->data))->currentInventorySize;
	bool invfull = false;
	bool alreadyhave = false;


	if (((PlayerInfo*)(peer->data))->inventory.items.size() == invsizee) {
		sendConsoleMsg(peer, "Your inventory is full! please upgrade it on the store.");
		alreadyhave = true;
	}

	bool isFullStock = false;
	bool isInInv = false;
	for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
	{

		if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == fItemid && ((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount >= 200) {


			sendConsoleMsg(peer, "You already reached the max count of the item!");

			isFullStock = true;
		}

		if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == fItemid && ((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount < 200)	isInInv = true;

	}

	if (isFullStock == true || alreadyhave == true)
	{
		success = false;
	}
	else
	{
		success = true;

		std::ifstream iffff("inventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");

		json jj;

		if (iffff.fail()) {
			iffff.close();


		}
		if (iffff.is_open()) {


		}

		iffff >> jj; //load


		std::ofstream oo("inventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
		if (!oo.is_open()) {
			cout << GetLastError() << endl;
			_getch();
		}

		//jj["items"][aposition]["aposition"] = aposition;

		if (isInInv == false)
		{

			for (int i = 0; i < ((PlayerInfo*)(peer->data))->currentInventorySize; i++)
			{
				int itemid = jj["items"][i]["itemid"];
				int quantity = jj["items"][i]["quantity"];

				if (itemid == 0 && quantity == 0)
				{
					jj["items"][i]["itemid"] = fItemid;
					jj["items"][i]["quantity"] = fQuantity;
					break;
				}

			}
			oo << jj << std::endl;


			InventoryItem item;
			item.itemID = fItemid;
			item.itemCount = fQuantity;
			((PlayerInfo*)(peer->data))->inventory.items.push_back(item);

			sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
		}
		else
		{
			for (int i = 0; i < ((PlayerInfo*)(peer->data))->currentInventorySize; i++)
			{
				int itemid = jj["items"][i]["itemid"];
				int quantity = jj["items"][i]["quantity"];

				if (itemid == fItemid)
				{
					jj["items"][i]["quantity"] = quantity + fQuantity;
					break;
				}

			}
			oo << jj << std::endl;


			for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
			{
				if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == fItemid)
				{
					((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount += fQuantity;
					sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
				}
			}

		}
	}
}

void SaveFindsItem(int fItemid, int fQuantity, ENetPeer* peer)
{

	std::ifstream iffff("inventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");

	json jj;

	if (iffff.fail()) {
		iffff.close();


	}
	if (iffff.is_open()) {


	}

	iffff >> jj; //load


	std::ofstream oo("inventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
	if (!oo.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}

	//jj["items"][aposition]["aposition"] = aposition;

	for (int i = 0; i < ((PlayerInfo*)(peer->data))->currentInventorySize; i++)
	{
		int itemid = jj["items"][i]["itemid"];
		int quantity = jj["items"][i]["quantity"];
		if (itemid == 0 && quantity == 0)
		{
			jj["items"][i]["itemid"] = fItemid;
			jj["items"][i]["quantity"] = fQuantity;
			break;
		}

	}
	oo << jj << std::endl;


	InventoryItem item;
	item.itemID = fItemid;
	item.itemCount = fQuantity;
	((PlayerInfo*)(peer->data))->inventory.items.push_back(item);

	sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
}


void RemoveInventoryItem(int fItemid, int fQuantity, ENetPeer* peer)
{
	std::ifstream iffff("inventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");

	json jj;

	if (iffff.fail()) {
		iffff.close();
		cout << "[!]  RemoveInventoryItem funkcijoje (ofstream dalyje) error: itemid - " << fItemid << ", kiekis - " << fQuantity << endl;

	}
	if (iffff.is_open()) {


	}

	iffff >> jj; //load


	std::ofstream oo("inventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
	if (!oo.is_open()) {
		cout << GetLastError() << " RemoveInventoryItem funkcijoje (ofstream dalyje) error: itemid - " << fItemid << ", kiekis - " << fQuantity << endl;
		_getch();
	}

	//jj["items"][aposition]["aposition"] = aposition;


	for (int i = 0; i < ((PlayerInfo*)(peer->data))->currentInventorySize; i++)
	{
		int itemid = jj["items"][i]["itemid"];
		int quantity = jj["items"][i]["quantity"];
		if (itemid == fItemid)
		{
			if (quantity - fQuantity == 0)
			{
				jj["items"][i]["itemid"] = 0;
				jj["items"][i]["quantity"] = 0;
			}
			else
			{
				jj["items"][i]["itemid"] = itemid;
				jj["items"][i]["quantity"] = quantity - fQuantity;
			}

			break;
		}

	}
	oo << jj << std::endl;

	for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
	{
		if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == fItemid)
		{
			if ((unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount > fQuantity && (unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount != fQuantity)
			{
				((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount -= fQuantity;
			}
			else
			{
				((PlayerInfo*)(peer->data))->inventory.items.erase(((PlayerInfo*)(peer->data))->inventory.items.begin() + i);
			}
			sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
		}
	}


}

void SaveInventoryWhenBuildingBlock(ENetPeer* peer)
{
	std::ifstream iffff("inventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");

	json jj;



	if (iffff.fail()) {
		iffff.close();
		cout << "[!] Klaida, skaitant inventoriu zaidejui " << ((PlayerInfo*)(peer->data))->rawName << " jam statant bloka worlde!" << endl;

	}
	if (iffff.is_open()) {


	}

	iffff >> jj; //load


	std::ofstream oo("inventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
	if (!oo.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}

	for (int i = 0; i < ((PlayerInfo*)(peer->data))->currentInventorySize; i++)
	{
		if (i < ((PlayerInfo*)(peer->data))->inventory.items.size())
		{
			jj["items"][i]["itemid"] = (unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID;
			jj["items"][i]["quantity"] = (unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount;
		}
		else
		{
			jj["items"][i]["itemid"] = 0;
			jj["items"][i]["quantity"] = 0;
		}
	}

	oo << jj << std::endl;

	if (oo.fail()) {
		oo.close();
		cout << "[!] Klaida, saugant inventoriu zaidejui " << ((PlayerInfo*)(peer->data))->rawName << " jam pastacius bloka worlde!" << endl;

	}
}


BYTE* packPlayerMoving(PlayerMoving* dataStruct)
{
	BYTE* data = new BYTE[64];
	for (int i = 0; i < 64; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 4, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 20, &dataStruct->plantingTree, 4);
	memcpy(data + 24, &dataStruct->x, 4);
	memcpy(data + 28, &dataStruct->y, 4);
	memcpy(data + 32, &dataStruct->XSpeed, 4);
	memcpy(data + 36, &dataStruct->YSpeed, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	return data;
}
string packPlayerMoving2(PlayerMoving* dataStruct)
{
	string data;
	data.resize(56);
	STRINT(data, 0) = dataStruct->packetType;
	STRINT(data, 4) = dataStruct->netID;
	STRINT(data, 12) = dataStruct->characterState;
	STRINT(data, 20) = dataStruct->plantingTree;
	STRINT(data, 24) = *(int*)&dataStruct->x;
	STRINT(data, 28) = *(int*)&dataStruct->y;
	STRINT(data, 32) = *(int*)&dataStruct->XSpeed;
	STRINT(data, 36) = *(int*)&dataStruct->YSpeed;
	STRINT(data, 44) = dataStruct->punchX;
	STRINT(data, 48) = dataStruct->punchY;
	return data;
}
string lockTileDatas(int visual, uint32_t owner, uint32_t adminLength, uint32_t* admins, bool isPublic = false, uint8_t bpm = 0) {
	string data;
	data.resize(4 + 2 + 4 + 4 + adminLength * 4 + 8);
	if (bpm) data.resize(data.length() + 4);
	data[2] = 0x01;
	if (isPublic) data[2] |= 0x80;
	data[4] = 3;
	data[5] = visual; // or 0x02
	STRINT(data, 6) = owner;
	//data[14] = 1;
	STRINT(data, 10) = adminLength;
	for (uint32_t i = 0; i < adminLength; i++) {
		STRINT(data, 14 + i * 4) = admins[i];
	}

	if (bpm) {
		STRINT(data, 10)++;
		STRINT(data, 14 + adminLength * 4) = -bpm;
	}
	return data;
}

uint8_t* lockTileData(uint32_t owner, uint32_t adminLength, uint32_t* admins) {
	uint8_t* data = new uint8_t[4 + 2 + 4 + 4 + adminLength * 4 + 8];
	memset(data, 0, 4 + 2 + 4 + 4 + adminLength * 4 + 8);
	data[2] = 0x1;
	data[4] = 3;
	*(uint32_t*)(data + 6) = owner;

	*(uint32_t*)(data + 10) = adminLength;
	for (uint32_t i = 0; i < adminLength; i++) {
		*(uint32_t*)(data + 14 + i * 4) = admins[i];
	}
	return data;
}
void sendLock(ENetPeer* peer, int x, int y, int lockid, uint32_t owner, uint32_t adminsize, uint32_t* admins)
{
	PlayerMoving pmov;
	pmov.packetType = 5;
	pmov.punchX = x;
	pmov.punchY = y;
	pmov.netID = -1;
	uint8_t* pmovpacked = packPlayerMoving(&pmov);
	*(uint32_t*)(pmovpacked + 52) = 4 + 22 + adminsize * 4;
	uint8_t* packet = new uint8_t[4 + 56 + 4 + 22 + adminsize * 4];
	memset(packet, 0, 4 + 56 + 4 + 22 + adminsize * 4);
	packet[0] = 4;
	memcpy(packet + 4, pmovpacked, 56);
	*(uint16_t*)(packet + 56 + 4) = lockid;
	uint8_t* tiledata = lockTileData(owner, adminsize, admins);
	memcpy(packet + 60 + 4, tiledata, 22 + adminsize + 4);
	ENetPacket* epacket = enet_packet_create(packet, 4 + 56 + 4 + 22 + adminsize * 4, ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, epacket);

	delete pmovpacked;
	delete packet;
	delete tiledata;
}
BYTE* packBlockVisual(BlockVisual* dataStruct)
{
	BYTE* data = new BYTE[72];
	for (int i = 0; i < 72; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 8, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	memcpy(data + 52, &dataStruct->charStat, 4);
	memcpy(data + 56, &dataStruct->blockid, 4);
	//memcpy(data + 58, &dataStruct->backgroundid, 4);
	memcpy(data + 60, &dataStruct->visual, 4);
	memcpy(data + 64, &dataStruct->displayblock, 4);


	return data;
}

PlayerMoving* unpackPlayerMoving(BYTE* data)
{
	PlayerMoving* dataStruct = new PlayerMoving;
	dataStruct->packetType = *(int*)(data);
	dataStruct->netID = *(int*)(data + 4);
	dataStruct->characterState = *(int*)(data + 12);
	dataStruct->plantingTree = *(int*)(data + 20);
	dataStruct->x = *(float*)(data + 24);
	dataStruct->y = *(float*)(data + 28);
	dataStruct->XSpeed = *(float*)(data + 32);
	dataStruct->YSpeed = *(float*)(data + 36);
	dataStruct->punchX = *(int*)(data + 44);
	dataStruct->punchY = *(int*)(data + 48);
	return dataStruct;
}

void SendPacket(int a1, string a2, ENetPeer* enetPeer)
{
	if (enetPeer)
	{
		ENetPacket* v3 = enet_packet_create(0, a2.length() + 5, 1);
		memcpy(v3->data, &a1, 4);
		//*(v3->data) = (DWORD)a1;
		memcpy((v3->data) + 4, a2.c_str(), a2.length());

		//cout << std::hex << (int)(char)v3->data[3] << endl;
		enet_peer_send(enetPeer, 0, v3);
	}
}
void SendPacketRaw2(int a1, void *packetData, size_t packetDataSize, void *a4, ENetPeer* peer, int packetFlag)
{
	ENetPacket *p;

	if (peer) // check if we have it setup
	{
		if (a1 == 4 && *((BYTE *)packetData + 12) & 8)
		{
			p = enet_packet_create(0, packetDataSize + *((DWORD *)packetData + 13) + 5, packetFlag);
			int four = 4;
			memcpy(p->data, &four, 4);
			memcpy((char *)p->data + 4, packetData, packetDataSize);
			memcpy((char *)p->data + packetDataSize + 4, a4, *((DWORD *)packetData + 13));
			enet_peer_send(peer, 0, p);

		}
		else
		{
			if (a1 == 192) {
				a1 = 4;
				p = enet_packet_create(0, packetDataSize + 5, packetFlag);
				memcpy(p->data, &a1, 4);
				memcpy((char *)p->data + 4, packetData, packetDataSize);
				enet_peer_send(peer, 0, p);


			}
			else {
				p = enet_packet_create(0, packetDataSize + 5, packetFlag);
				memcpy(p->data, &a1, 4);
				memcpy((char *)p->data + 4, packetData, packetDataSize);
				enet_peer_send(peer, 0, p);


			}
		}
	}

	delete packetData;
}
void SendPacketRaw(int a1, void* packetData, size_t packetDataSize, void* a4, ENetPeer* peer, int packetFlag)
{
	ENetPacket* p;

	if (peer) // check if we have it setup
	{
		if (a1 == 4 && *((BYTE*)packetData + 12) & 8)
		{
			p = enet_packet_create(0, packetDataSize + *((DWORD*)packetData + 13) + 5, packetFlag);
			int four = 4;
			memcpy(p->data, &four, 4);
			memcpy((char*)p->data + 4, packetData, packetDataSize);
			memcpy((char*)p->data + packetDataSize + 4, a4, *((DWORD*)packetData + 13));
			enet_peer_send(peer, 0, p);

		}
		else
		{
			if (a1 == 192) {
				a1 = 4;
				p = enet_packet_create(0, packetDataSize + 5, packetFlag);
				memcpy(p->data, &a1, 4);
				memcpy((char*)p->data + 4, packetData, packetDataSize);
				enet_peer_send(peer, 0, p);

				/*p = enet_packet_create(0, packetDataSize + *((DWORD *)packetData + 16) + 5, packetFlag);
				int four = 4;
				memcpy(p->data, &four, 4);
				memcpy((char *)p->data + 4, packetData, packetDataSize);
				memcpy((char *)p->data + packetDataSize + 4, a4, *((DWORD *)packetData + 16));
				enet_peer_send(peer, 0, p);*/
			}
			else {
				p = enet_packet_create(0, packetDataSize + 5, packetFlag);
				memcpy(p->data, &a1, 4);
				memcpy((char*)p->data + 4, packetData, packetDataSize);
				enet_peer_send(peer, 0, p);


			}
		}
	}

	delete packetData;
}
void updateGuild(ENetPeer* peer) {
	string guildname = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild);
	if (guildname != "") {
		std::ifstream ifff("guilds/" + guildname + ".json");
		if (ifff.fail()) {
			ifff.close();
			cout << "[!] Failed loading guilds/" + guildname + ".json! From " + ((PlayerInfo*)(peer->data))->displayName + "." << endl;
			((PlayerInfo*)(peer->data))->guild = "";
			updateGuild;
		}
		json j;
		ifff >> j;

		int gfbg, gffg;

		string gstatement, gleader;

		vector<string> gmembers;

		gfbg = j["backgroundflag"];
		gffg = j["foregroundflag"];
		gstatement = j["GuildStatement"];
		gleader = j["Leader"];
		for (int i = 0; i < j["Member"].size(); i++) {
			gmembers.push_back(j["Member"][i]);
		}

		if (find(gmembers.begin(), gmembers.end(), ((PlayerInfo*)(peer->data))->rawName) == gmembers.end()) {
			((PlayerInfo*)(peer->data))->guild = "";
		}
		else {
			((PlayerInfo*)(peer->data))->guildBg = gfbg;
			((PlayerInfo*)(peer->data))->guildFg = gffg;
			((PlayerInfo*)(peer->data))->guildStatement = gstatement;
			((PlayerInfo*)(peer->data))->guildLeader = gleader;
			((PlayerInfo*)(peer->data))->guildMembers = gmembers;
		}

		ifff.close();
	}
}
void addInventoryItem(ENetPeer* peer, int id, int netID, int amount) {
	PlayerMoving pmov;
	memset(&pmov, 0, sizeof(PlayerMoving));
	pmov.netID = netID;
	pmov.plantingTree = id;
	pmov.packetType = 13;
	string packet;
	packet.resize(4);
	packet[0] = 4;
	packet += packPlayerMoving2(&pmov);
	packet[4 + 3] = amount;
	ENetPacket* epacket = enet_packet_create(&packet[0],
		packet.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, epacket);
}

void removeInventoryItem(ENetPeer* peer, int id, int amount) {

	PlayerMoving pmov;
	pmov.netID = -1;
	pmov.plantingTree = id;
	pmov.packetType = 13;
	string packet;
	packet.resize(4);
	packet[0] = 4;
	packet += packPlayerMoving2(&pmov);
	packet[4 + 2] = amount;
	ENetPacket* epacket = enet_packet_create(&packet[0],
		packet.length(),
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, epacket);
}
int HasItemsInInv(ENetPeer* peer, int itemId, int count);
bool HasInventoryFull(ENetPeer* peer);
bool HasInventoryEmpty(ENetPeer* peer);
void AddItemToInv(ENetPeer* peer, int itemId, int count);

void sendDrop(ENetPeer* peer, int netID, int x, int y, int item, int count, BYTE specialEffect)
{
	if (item >= 7068) return;
	if (item < 0) return;
	ENetPeer* currentPeer;
	string name = "";
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			PlayerMoving data;
			data.packetType = 14;
			data.x = x;
			data.y = y;
			data.netID = netID;
			data.plantingTree = item;
			float val = count; // item count
			BYTE val2 = specialEffect;
			BYTE* raw = packPlayerMoving(&data);
			memcpy(raw + 16, &val, 4);
			memcpy(raw + 1, &val2, 1);

			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
}
void DropItem(ENetPeer* peer, int netID, int x, int y, int item, int count, BYTE specialEffect)
{
	WorldInfo* world = getPlyersWorld(peer);
	if (!world) return;
	if (item >= maxItems) return;
	if (item < 0) return;
	DroppedItem itemDropped;
	itemDropped.id = item;
	itemDropped.count = count;
	itemDropped.x = x;
	itemDropped.y = y;
	itemDropped.uid = world->droppedItemUid++;
	world->droppedItems.push_back(itemDropped);
	sendDrop(peer, netID, x, y, item, count, specialEffect);
}
void SendDropSingle(ENetPeer* peer, int netID, int x, int y, int item, int count, BYTE specialEffect)
{
	if (item >= maxItems) return;
	if (item < 0) return;

	PlayerMoving data;
	data.packetType = 14;
	data.x = x;
	data.y = y;
	data.netID = netID;
	data.plantingTree = item;
	float val = count; // item count
	BYTE val2 = specialEffect;

	BYTE* raw = packPlayerMoving(&data);
	memcpy(raw + 16, &val, 4);
	memcpy(raw + 1, &val2, 1);

	SendPacketRaw(4, raw, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
}
void SendTradeEffect(ENetPeer* peer, int id, int netIDsrc, int netIDdst, int timeMs)
{
	PlayerMoving data;
	data.packetType = 0x13;
	data.punchX = id;
	data.punchY = id;

	BYTE* raw = packPlayerMoving(&data);
	int netIdSrc = netIDsrc;
	int netIdDst = netIDdst;
	int three = 3;
	int n1 = timeMs;
	memcpy(raw + 3, &three, 1);
	memcpy(raw + 4, &netIdDst, 4);
	memcpy(raw + 8, &netIdSrc, 4);
	memcpy(raw + 20, &n1, 4);

	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			BYTE* raw2 = new BYTE[56];
			memcpy(raw2, raw, 56);
			SendPacketRaw(4, raw2, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
	delete raw;
}
void SendTake(ENetPeer* peer, int netID, int x, int y, int item)
{

	if (item >= 9999) return;
	if (item < 0) return;
	ENetPeer * currentPeer;
	string name = "";


	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			PlayerMoving data;
			data.packetType = 14;
			data.x = x;
			data.y = y;
			data.netID = netID;
			data.plantingTree = item;

			BYTE* raw = packPlayerMoving(&data);

			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_EVENT_TYPE_RECEIVE);
		}
	}
}

void onPeerConnect(ENetPeer* peer)
{
	ENetPeer* currentPeer;

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (peer != currentPeer)
		{
			if (isHere(peer, currentPeer))
			{
				string netIdS = std::to_string(((PlayerInfo*)(currentPeer->data))->netID);
				string userids = std::to_string(((PlayerInfo*)(currentPeer->data))->userID);
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS + "\nuserID|" + userids + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(currentPeer->data))->x) + "|" + std::to_string(((PlayerInfo*)(currentPeer->data))->y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);

				enet_peer_send(peer, 0, packet);
				delete p.data;
				string netIdS2 = std::to_string(((PlayerInfo*)(peer->data))->netID);
				GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + netIdS2 + "\nuserID|" + userids + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(peer->data))->x) + "|" + std::to_string(((PlayerInfo*)(peer->data))->y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
				ENetPacket* packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;
				//enet_host_flush(server);
			}
		}
	}

}

void updateDoor(ENetPeer* peer, int foreground, int x, int y, string text)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	int hmm = 8;
	int text_len = text.length();
	int lol = 0;
	int wut = 5;
	int yeh = hmm + 3 + 1;
	int idk = 15 + text_len;
	int is_locked = 0;
	int bubble_type = 1;
	int ok = 52 + idk;
	int kek = ok + 4;
	int yup = ok - 8 - idk;
	int four = 4;
	int magic = 56;
	int wew = ok + 5 + 4;
	int wow = magic + 4 + 5;

	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, four); //4
	memcpy(data + yeh, &hmm, four); //8
	memcpy(data + yup, &x, 4); //12
	memcpy(data + yup + 4, &y, 4); //16
	memcpy(data + 4 + yup + 4, &idk, four); //20
	memcpy(data + magic, &foreground, 2); //22
	memcpy(data + four + magic, &lol, four); //26
	memcpy(data + magic + 4 + four, &bubble_type, 1); //27
	memcpy(data + wow, &text_len, 2); //data + wow = text_len, pos 29
	memcpy(data + 2 + wow, text.c_str(), text_len); //data + text_len_len + text_len_offs = text, pos 94
	memcpy(data + ok, &is_locked, four); //98
	memcpy(p->data, &four, four); //4
	memcpy((char*)p->data + four, data, kek); //kek = data_len
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			enet_peer_send(currentPeer, 0, p);
		}
	}
	delete data;
}
/*void Respawn(ENetPeer* peer) {
	int x = 3040;
	int y = 736;

	WorldInfo* world = getPlyersWorld(peer);
	if (world)
	{


		ENetPeer* currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {

				int x = ((PlayerInfo*)(peer->data))->x;
				int y = ((PlayerInfo*)(peer->data))->y;
				GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 3), x, (y + 8)));

				ENetPacket* packetd = enet_packet_create(psp.data,
					psp.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packetd);
				delete psp.data;

				string text = "action|play_sfx\nfile|audio/male_scream.wav\ndelayMS|0\n";
				BYTE* data = new BYTE[5 + text.length()];
				BYTE zero = 0;
				int type = 3;
				memcpy(data, &type, 4);
				memcpy(data + 4, text.c_str(), text.length());
				memcpy(data + 4 + text.length(), &zero, 1);

				{
					ENetPacket* packetres = enet_packet_create(data,
						5 + text.length(),
						ENET_PACKET_FLAG_RELIABLE);

					if (isHere(peer, currentPeer)) {
						enet_peer_send(currentPeer, 0, packetres);

					}
				}
			}
		}

		for (int i = 0; i < world->width * world->height; i++)
		{
			if (world->items[i].foreground == 6) {
				x = (i % world->width) * 32;
				y = (i / world->width) * 32;
				//world->items[i].foreground = 8;
			}
		}
		{
			PlayerMoving data;
			data.packetType = 0x0;
			data.characterState = 0x924; // animation
			data.x = x;
			data.y = y;
			data.punchX = -1;
			data.punchY = -1;
			data.XSpeed = 0;
			data.YSpeed = 0;
			data.netID = ((PlayerInfo*)(peer->data))->netID;
			data.plantingTree = 0x0; // 0x0
			SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
		}

		{
			int x = 3040;
			int y = 736;


			for (int i = 0; i < world->width * world->height; i++)
			{
				if (world->items[i].foreground == 6) {
					x = (i % world->width) * 32;
					y = (i / world->width) * 32;
					//world->items[i].foreground = 8;
				}
			}
			GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x, y));
			memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
			ENetPacket* packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);


			enet_peer_send(peer, 0, packet2);
			delete p2.data;
			//enet_host_flush(server);
		}
		{
			int x = 3040;
			int y = 736;


			for (int i = 0; i < world->width * world->height; i++)
			{
				if (world->items[i].foreground == 6) {
					x = (i % world->width) * 32;
					y = (i / world->width) * 32;
					//world->items[i].foreground = 8;
				}
			}
			GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
			memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
			ENetPacket* packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);


			enet_peer_send(peer, 0, packet2);
			delete p2.data;
			enet_host_flush(server);
		}
	}
	if (((PlayerInfo*)(peer->data))->ischeck == false)
	{
		GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x, y));
		memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
		ENetPacket* packet2 = enet_packet_create(p2.data,
			p2.len,
			ENET_PACKET_FLAG_RELIABLE);


		enet_peer_send(peer, 0, packet2);
		delete p2.data;
	}
	else
	{
		GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), ((PlayerInfo*)(peer->data))->checkx, ((PlayerInfo*)(peer->data))->checky));
		memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
		ENetPacket* packet2 = enet_packet_create(p2.data,
			p2.len,
			ENET_PACKET_FLAG_RELIABLE);


		enet_peer_send(peer, 0, packet2);
		delete p2.data;
	}
}*/
void doorlocked(ENetPeer* peer, int foreground, int x, int y, string text)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	int hmm = 8;
	int text_len = text.length();
	int lol = 0;
	int wut = 5;
	int yeh = hmm + 3 + 1;
	int idk = 15 + text_len;
	int is_locked = -1;
	int bubble_type = 1;
	int ok = 52 + idk;
	int kek = ok + 4;
	int yup = ok - 8 - idk;
	int four = 4;
	int magic = 56;
	int wew = ok + 5 + 4;
	int wow = magic + 4 + 5;

	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, four); //4
	memcpy(data + yeh, &hmm, four); //8
	memcpy(data + yup, &x, 4); //12
	memcpy(data + yup + 4, &y, 4); //16
	memcpy(data + 4 + yup + 4, &idk, four); //20
	memcpy(data + magic, &foreground, 2); //22
	memcpy(data + four + magic, &lol, four); //26
	memcpy(data + magic + 4 + four, &bubble_type, 1); //27
	memcpy(data + wow, &text_len, 2); //data + wow = text_len, pos 29
	memcpy(data + 2 + wow, text.c_str(), text_len); //data + text_len_len + text_len_offs = text, pos 94
	memcpy(data + ok, &is_locked, four); //98
	memcpy(p->data, &four, four); //4
	memcpy((char*)p->data + four, data, kek); //kek = data_len
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			enet_peer_send(currentPeer, 0, p);
		}
	}
	delete data;
}
void updateGayItem(ENetPeer* peer, int foreground, int x, int y, string text)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	int hmm = 8;
	int text_len = text.length();
	int lol = 0;
	int wut = 5;
	int yeh = hmm + 3 + 1;
	int idk = 15 + text_len;
	int is_locked = 0;
	int bubble_type = 1;
	int ok = 52 + idk;
	int kek = ok + 4;
	int yup = ok - 8 - idk;
	int four = 4;
	int magic = 56;
	int wew = ok + 5 + 4;
	int wow = magic + 4 + 5;

	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, four); //4
	memcpy(data + yeh, &hmm, four); //8
	memcpy(data + yup, &x, 4); //12
	memcpy(data + yup + 4, &y, 4); //16
	memcpy(data + 4 + yup + 4, &idk, four); //20
	memcpy(data + magic, &foreground, 2); //22
	memcpy(data + four + magic, &lol, four); //26
	memcpy(data + magic + 4 + four, &bubble_type, 1); //27
	memcpy(data + wow, &text_len, 2); //data + wow = text_len, pos 29
	memcpy(data + 2 + wow, text.c_str(), text_len); //data + text_len_len + text_len_offs = text, pos 94
	memcpy(data + ok, &is_locked, four); //98
	memcpy(p->data, &four, four); //4
	memcpy((char*)p->data + four, data, kek); //kek = data_len
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			enet_peer_send(currentPeer, 0, p);
		}
	}
	delete data;
}
void updateDisplay(ENetPeer* peer, int foreground, int x, int y, string text, int background)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	int hmm = 8, wot = text.length(), lol = 0x00010000, wut = 5;
	int yeh = hmm + 3 + 1, idk = 15 + wot, lmao = -1, yey = 2; //idk = text_len + 15, wut = type(?), wot = text_len, yey = len of text_len
	int ok = 52 + idk;
	int kek = ok + 4, yup = ok - 8 - idk;
	int thonk = 4, magic = 56, wew = ok + 5 + 4;
	int wow = magic + 4 + 5;
	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, thonk);
	memcpy(data + yeh, &hmm, thonk); //read discord
	memcpy(data + yup, &x, 4);
	memcpy(data + yup + 4, &y, 4);
	memcpy(data + 4 + yup + 4, &idk, thonk);
	memcpy(data + magic, &foreground, yey);
	memcpy(data + magic + 2, &background, yey); // gai?
	memcpy(data + thonk + magic, &lol, thonk);
	memcpy(data + magic + 4 + thonk, &yey, 1);
	memcpy(data + wow, &wot, yey); //data + wow = text_len
	memcpy(data + yey + wow, text.c_str(), wot); //data + text_len_len + text_len_offs = text
	memcpy(data + ok, &lmao, thonk); //end ?
	memcpy(p->data, &thonk, thonk);
	memcpy((char*)p->data + thonk, data, kek); //kek = data_len
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			enet_peer_send(currentPeer, 0, p);
		}
	}
	delete data;
}
uint8_t* magplantTileData(uint16_t itemid, uint16_t itemamount, uint8_t magnet_on, uint8_t remote_on) {
	uint8_t* data = new uint8_t[15];
	memset(data, 0, 15);
	data[0] = 0x3E;
	*(uint16_t*)(data + 1) = itemid;
	*(uint16_t*)(data + 5) = itemamount;
	*(uint8_t*)(data + 9) = magnet_on;
	*(uint8_t*)(data + 10) = remote_on;
	*(uint8_t*)(data + 12) = 1;
	return data;
}
void sendMag(ENetPeer* peer, int x, int y, uint16_t itemid, uint16_t itemamount, uint8_t magneton, uint8_t remoteon)
{
	PlayerMoving pmov;
	pmov.packetType = 5;
	pmov.characterState = 8;
	pmov.punchX = x;
	pmov.punchY = y;
	pmov.netID = -1;
	uint8_t* pmovpacked = packPlayerMoving(&pmov);
	*(uint32_t*)(pmovpacked + 52) = 15 + 8;
	uint8_t* packet = new uint8_t[4 + 56 + 15 + 8];
	memset(packet, 0, 4 + 56 + 15 + 8);
	packet[0] = 4;
	memcpy(packet + 4, pmovpacked, 56);
	*(uint16_t*)(packet + 4 + 56) = 5638; // magplant id
	*(uint16_t*)(packet + 4 + 56 + 6) = 1;
	uint8_t* tiledata = magplantTileData(itemid, itemamount, magneton, remoteon);
	memcpy(packet + 4 + 56 + 8, tiledata, 15);
	ENetPacket* epacket = enet_packet_create(packet, 4 + 56 + 8 + 15, ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, epacket);

	delete pmovpacked;
	delete packet;
	delete tiledata;
}
void updateWorldLock(ENetPeer* peer, int foreground, int x, int y, string text, int background, PlayerInfo* info)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	int hmm = 8, wot = text.length(), lol = info->blockvisual, wut = 5;
	int yeh = hmm + 3 + 1, idk = 15 + wot, lmao = -1, yey = 2; //idk = text_len + 15, wut = type(?), wot = text_len, yey = len of text_len
	int ok = 52 + idk;
	int kek = ok + 4, yup = ok - 8 - idk;
	int thonk = 4, magic = 56, wew = ok + 5 + 4;
	int wow = magic + 4 + 5;
	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, thonk);
	memcpy(data + yeh, &hmm, thonk); //read discord
	memcpy(data + yup, &x, 4);
	memcpy(data + yup + 4, &y, 4);
	memcpy(data + 4 + yup + 4, &idk, thonk);
	memcpy(data + magic, &foreground, yey);
	memcpy(data + magic + 2, &background, yey); // gai?
	memcpy(data + thonk + magic, &lol, thonk);
	memcpy(data + magic + 4 + thonk, &yey, 1);
	memcpy(data + wow, &wot, yey); //data + wow = text_len
	memcpy(data + yey + wow, text.c_str(), wot); //data + text_len_len + text_len_offs = text
	memcpy(data + ok, &lmao, thonk); //end ?
	memcpy(p->data, &thonk, thonk);
	memcpy((char*)p->data + thonk, data, kek); //kek = data_len
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			enet_peer_send(currentPeer, 0, p);
		}
	}
	delete data;
}
void updateRotatedItem(ENetPeer* peer, int foreground, int x, int y, string text, int background)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	int hmm = 8, wot = text.length(), lol = 0x00200000, wut = 5;
	int yeh = hmm + 3 + 1, idk = 15 + wot, lmao = -1, yey = 2; //idk = text_len + 15, wut = type(?), wot = text_len, yey = len of text_len
	int ok = 52 + idk;
	int kek = ok + 4, yup = ok - 8 - idk;
	int thonk = 4, magic = 56, wew = ok + 5 + 4;
	int wow = magic + 4 + 5;
	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, thonk);
	memcpy(data + yeh, &hmm, thonk); //read discord
	memcpy(data + yup, &x, 4);
	memcpy(data + yup + 4, &y, 4);
	memcpy(data + 4 + yup + 4, &idk, thonk);
	memcpy(data + magic, &foreground, yey);
	memcpy(data + magic + 2, &background, yey); // gai?
	memcpy(data + thonk + magic, &lol, thonk);
	memcpy(data + magic + 4 + thonk, &yey, 1);
	memcpy(data + wow, &wot, yey); //data + wow = text_len
	memcpy(data + yey + wow, text.c_str(), wot); //data + text_len_len + text_len_offs = text
	memcpy(data + ok, &lmao, thonk); //end ?
	memcpy(p->data, &thonk, thonk);
	memcpy((char*)p->data + thonk, data, kek); //kek = data_len
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			enet_peer_send(currentPeer, 0, p);
		}
	}
	delete data;
}
class Player {
public:
	static void OnConsoleMessage(ENetPeer* peer, string text);
	static void OnTalkBubble(ENetPeer* peer, int netID, string text, int chatColor, bool isOverlay);
	static void OnAddNotification(ENetPeer* peer, string text, string audiosound, string interfaceimage);
	static void OnStartAcceptLogon(ENetPeer* peer, int itemdathash);
	static void OnRemove(ENetPeer* peer, int netID);
	static void OnSendToServer(ENetPeer* peer, int userID, int token, string ip, int port, string doorId, int lmode); // no need other args, sub servers done&working already... using fake data etc.
	static void SendTileAnimation(ENetPeer* peer, int x, int y, int causedBy, int tile);
	static void PlayAudio(ENetPeer* peer, string audioFile, int delayMS);
	static void showWrong(ENetPeer* peer, string itemFind, string listFull);
	static void OnZoomCamera(ENetPeer* peer, float value1, int value2);
	static void SmoothZoom(ENetPeer* peer);
	static void OnRaceStart(ENetPeer* peer, int netID);
	static void OnRaceEnd(ENetPeer* peer, int netID);
	static void OnSetCurrentWeather(ENetPeer* peer, int weather);
	static void OnPlayPositioned(ENetPeer* peer, string audiofile, int netID, bool broadcastInWorld, ENetPacket* pk);
	static void OnCountdownStart(ENetPeer* peer, int netID, int time, int score);
	static void OnCountdownUpdate(ENetPeer* peer, int netID, int score);
	static void OnCountdownEnd(ENetPeer* peer);
	static void OnStartTrade(ENetPeer* peer, int netID1, int netID2);
	static void OnTextOverlay(ENetPeer* peer, string text);
	static void OnForceTradeEnd(ENetPeer* peer);
	static void OnFailedToEnterWorld(ENetPeer* peer);
	static void OnNameChanged(ENetPeer* peer, int netID, string name);
	static void OnTradeStatus(ENetPeer* peer, int netIDOther, string offerstatus, string offer);
	static void OnDialogRequest(ENetPeer* peer, string args);
	static void OnKilled(ENetPeer* peer, int netID);
	static void OnSetFreezeState(ENetPeer* peer, int state, int netID);
	static void OnSetPos(ENetPeer* peer, int netID, int x, int y);
	static void OnFlagMay2019(ENetPeer* peer, int state, int netID);
	static void OnBillboardChange(ENetPeer* peer, int netID); //testing billboards
	static void SendTilePickup(ENetPeer* peer, int itemid, int netID, float x, float y, int itemcount, int itemamount);
	static void OnInvis(ENetPeer* peer, int state, int netID);
	static void OnChangeSkin(ENetPeer* peer, int skinColor, int netID);
	static void SetRespawnPos(ENetPeer* peer, int posX, int posY, int netID);
	static void OnSetBux(ENetPeer* peer, int gems, int accountstate);
	static void OnParticleEffect(ENetPeer* peer, int effect, float x, float y, int delay);
	static void SetHasGrowID(ENetPeer* peer, int status, string username, string password);
	static void Ping(ENetPeer* peer);
};
void Player::OnInvis(ENetPeer* peer, int state, int netID) {
	GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), state));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}
void Player::OnConsoleMessage(ENetPeer * peer, string text)
{
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), text));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
} 

void Player::OnSetBux(ENetPeer * peer, int gems, int accountstate)
{
	GamePacket p = packetEnd(appendInt(appendInt(appendString(createPacket(), "OnSetBux"), gems), accountstate));
	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnNameChanged(ENetPeer * peer, int netID, string name)
{
	GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "`0`0" + name));
	memcpy(p3.data + 8, &netID, 4);
	ENetPacket * packet3 = enet_packet_create(p3.data,
		p3.len,
		ENET_PACKET_FLAG_RELIABLE);
	ENetPeer * currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			enet_peer_send(currentPeer, 0, packet3);
		}
	}
	delete p3.data;
}

void Player::PlayAudio(ENetPeer* peer, string audioFile, int delayMS)
{
	string text = "action|play_sfx\nfile|" + audioFile + "\ndelayMS|" + to_string(delayMS) + "\n";
	BYTE* data = new BYTE[5 + text.length()];
	BYTE zero = 0;
	int type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);
	ENetPacket* packet = enet_packet_create(data,
		5 + text.length(),
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet);
	delete data;
}
void Player::OnFailedToEnterWorld(ENetPeer* peer) {
	GamePacket p = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnTextOverlay(ENetPeer* peer, string text) {
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), text));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnKilled(ENetPeer* peer, int netID) {
	GamePacket p = packetEnd(appendString(createPacket(), "OnKilled"));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}
void Player::OnTalkBubble(ENetPeer* peer, int netID, string text, int chatColor, bool isOverlay)
{
	if (isOverlay == true) {
		GamePacket p = packetEnd(appendIntx(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"),
			((PlayerInfo*)(peer->data))->netID), text), chatColor), 1));

		ENetPacket* packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;
	}
	else
	{
		GamePacket p = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"),
			((PlayerInfo*)(peer->data))->netID), text), chatColor));

		ENetPacket* packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;
	}
}
void Player::SetRespawnPos(ENetPeer* peer, int posX, int posY, int netID) {
	GamePacket p22 = packetEnd(appendInt(appendString(createPacket(), "SetRespawnPos"), posX + posY)); // (world->width * posY)
	memcpy(p22.data + 8, &netID, 4);
	ENetPacket* packet22 = enet_packet_create(p22.data,
		p22.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet22);
	delete p22.data;
}
void updateWater(ENetPeer* peer, int foreground, int x, int y, string text, int background)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	int hmm = 8, wot = text.length(), lol = 0x04000000, wut = 5;
	int yeh = hmm + 3 + 1, idk = 15 + wot, lmao = -1, yey = 2; //idk = text_len + 15, wut = type(?), wot = text_len, yey = len of text_len
	int ok = 52 + idk;
	int kek = ok + 4, yup = ok - 8 - idk;
	int thonk = 4, magic = 56, wew = ok + 5 + 4;
	int wow = magic + 4 + 5;
	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, thonk);
	memcpy(data + yeh, &hmm, thonk); //read discord
	memcpy(data + yup, &x, 4);
	memcpy(data + yup + 4, &y, 4);
	memcpy(data + 4 + yup + 4, &idk, thonk);
	memcpy(data + magic, &foreground, yey);
	memcpy(data + magic + 2, &background, yey); // gai?
	memcpy(data + thonk + magic, &lol, thonk);
	memcpy(data + magic + 4 + thonk, &yey, 1);
	memcpy(data + wow, &wot, yey); //data + wow = text_len
	memcpy(data + yey + wow, text.c_str(), wot); //data + text_len_len + text_len_offs = text
	memcpy(data + ok, &lmao, thonk); //end ?
	memcpy(p->data, &thonk, thonk);
	memcpy((char*)p->data + thonk, data, kek); //kek = data_len
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			enet_peer_send(currentPeer, 0, p);
		}
	}
	delete data;
}
void updateFire(ENetPeer* peer, int foreground, int x, int y, string text, int background)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	int hmm = 8, wot = text.length(), lol = 0x10000000, wut = 5;
	int yeh = hmm + 3 + 1, idk = 15 + wot, lmao = -1, yey = 2; //idk = text_len + 15, wut = type(?), wot = text_len, yey = len of text_len
	int ok = 52 + idk;
	int kek = ok + 4, yup = ok - 8 - idk;
	int thonk = 4, magic = 56, wew = ok + 5 + 4;
	int wow = magic + 4 + 5;
	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, thonk);
	memcpy(data + yeh, &hmm, thonk); //read discord
	memcpy(data + yup, &x, 4);
	memcpy(data + yup + 4, &y, 4);
	memcpy(data + 4 + yup + 4, &idk, thonk);
	memcpy(data + magic, &foreground, yey);
	memcpy(data + magic + 2, &background, yey); // gai?
	memcpy(data + thonk + magic, &lol, thonk);
	memcpy(data + magic + 4 + thonk, &yey, 1);
	memcpy(data + wow, &wot, yey); //data + wow = text_len
	memcpy(data + yey + wow, text.c_str(), wot); //data + text_len_len + text_len_offs = text
	memcpy(data + ok, &lmao, thonk); //end ?
	memcpy(p->data, &thonk, thonk);
	memcpy((char*)p->data + thonk, data, kek); //kek = data_len
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			enet_peer_send(currentPeer, 0, p);
		}
	}
	delete data;
}


void sendTileData(ENetPeer* peer, int x, int y, int visual, uint16_t fgblock, uint16_t bgblock, string tiledata) {
	PlayerMoving pmov;
	pmov.packetType = 5;
	pmov.characterState = 0;
	pmov.x = 0;
	pmov.y = 0;
	pmov.XSpeed = 0;
	pmov.YSpeed = 0;
	pmov.plantingTree = 0;
	pmov.punchX = x;
	pmov.punchY = y;
	pmov.netID = 0;

	string packetstr;
	packetstr.resize(4);
	packetstr[0] = 4;
	packetstr += packPlayerMoving2(&pmov);
	packetstr[16] = 8;
	packetstr.resize(packetstr.size() + 4);
	STRINT(packetstr, 52 + 4) = tiledata.size() + 4;
	STR16(packetstr, 56 + 4) = fgblock;
	STR16(packetstr, 58 + 4) = bgblock;
	packetstr += tiledata;

	ENetPacket* packet = enet_packet_create(&packetstr[0],
		packetstr.length(),
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet);
}
#include "packet_initialize/display_block.h"

void UpdateDisplayVisuals(ENetPeer* peer, int foreground, int x, int y, int background, int itemid, bool sendPacketToEveryone = true)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = 0x56;
	sign.y = 0x15;
	sign.punchX = 0x56;
	sign.punchY = 0x15;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = 0x0b82;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

	int plength = 73;
	BYTE* raw = new BYTE[plength];
	memset(raw, 0, plength);
	InitializePacketWithDisplayBlock(raw);

	memcpy(raw + 44, &x, sizeof(int));
	memcpy(raw + 48, &y, sizeof(int));
	memcpy(raw + 56, &foreground, sizeof(short));
	memcpy(raw + 58, &background, sizeof(short));
	memcpy(raw + 65, &itemid, sizeof(int));

	ENetPacket* p = enet_packet_create(0, plength + 4, ENET_PACKET_FLAG_RELIABLE);
	int four = 4;
	memcpy(p->data, &four, sizeof(int));
	memcpy((char*)p->data + 4, raw, plength);

	if (sendPacketToEveryone)
	{
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				enet_peer_send(currentPeer, 0, p);
			}
		}
		delete raw;
	}
	else
	{
		enet_peer_send(peer, 0, p);
		delete raw;
	}
}

void UpdateUnlockedDoorVisuals(ENetPeer* peer, int foreground, int x, int y, int background, string text, bool sendPacketToEveryone = true, int visuals = 0)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = 0x56;
	sign.y = 0x15;
	sign.punchX = 0x56;
	sign.punchY = 0x15;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = 0x0b82;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

	BYTE a = 0x00; // 0x08 for locked
	BYTE b = 0xeb; // 0x98 for locked
	uint32_t c = 0xfdfdfdfd;
	short textLen = (short)text.size();
	int plength = 73 + textLen;
	BYTE* raw = new BYTE[plength];
	memset(raw, 0, plength);
	InitializePacketWithUnlockedDoor(raw);
	memcpy(raw + 44, &x, sizeof(int));
	memcpy(raw + 48, &y, sizeof(int));
	memcpy(raw + 56, &foreground, sizeof(short));
	memcpy(raw + 58, &background, sizeof(short));
	memcpy(raw + 60, &visuals, sizeof(int));
	memcpy(raw + 65, &textLen, sizeof(short));
	memcpy(raw + 67, text.c_str(), textLen);
	memcpy(raw + 67 + textLen, &a, 1);
	memcpy(raw + 68 + textLen, &b, 1);
	memcpy(raw + 69 + textLen, &c, 4);

	ENetPacket* p = enet_packet_create(0, plength + 4, ENET_PACKET_FLAG_RELIABLE);
	int four = 4;
	memcpy(p->data, &four, sizeof(int));
	memcpy((char*)p->data + 4, raw, plength);

	if (sendPacketToEveryone)
	{
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				enet_peer_send(currentPeer, 0, p);
			}
		}
		delete raw;
	}
	else
	{
		enet_peer_send(peer, 0, p);
		delete raw;
	}
}


void UpdateLockedDoorVisuals(ENetPeer* peer, int foreground, int x, int y, int background, string text, bool sendPacketToEveryone = true, int visuals = 0)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = 0x56;
	sign.y = 0x15;
	sign.punchX = 0x56;
	sign.punchY = 0x15;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = 0x0b82;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

	BYTE a = 0x08; // 0x00 for unlocked
	BYTE b = 0x98; // 0xeb for unlocked
	uint32_t c = 0xfdfdfdfd;
	short textLen = (short)text.size();
	int plength = 73 + textLen;
	BYTE* raw = new BYTE[plength];
	memset(raw, 0, plength);
	InitializePacketWithUnlockedDoor(raw);
	memcpy(raw + 44, &x, sizeof(int));
	memcpy(raw + 48, &y, sizeof(int));
	memcpy(raw + 56, &foreground, sizeof(short));
	memcpy(raw + 58, &background, sizeof(short));
	memcpy(raw + 60, &visuals, sizeof(int));
	memcpy(raw + 65, &textLen, sizeof(short));
	memcpy(raw + 67, text.c_str(), textLen);
	memcpy(raw + 67 + textLen, &a, 1);
	memcpy(raw + 68 + textLen, &b, 1);
	memcpy(raw + 69 + textLen, &c, 4);

	ENetPacket* p = enet_packet_create(0, plength + 4, ENET_PACKET_FLAG_RELIABLE);
	int four = 4;
	memcpy(p->data, &four, sizeof(int));
	memcpy((char*)p->data + 4, raw, plength);

	if (sendPacketToEveryone)
	{
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				enet_peer_send(currentPeer, 0, p);
			}
		}
		delete raw;
	}
	else
	{
		enet_peer_send(peer, 0, p);
		delete raw;
	}
}

void UpdateTreeVisuals(ENetPeer* peer, int foreground, int x, int y, int background, int fruitCount) {
	//int val = 1 + rand() % 4;
	string text = "tree";
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

	int hmm = 8;
	int text_len = 4;
	int zero = 0;
	int packetType = 5;
	int yeh = hmm + 3 + 1;
	int idk = 15 + text_len;
	int blockState = 0;
	int bubble_type = 4;
	int ok = 52 + idk;
	int packetSize = ok + 4;
	int yup = ok - 8 - idk;
	int four = 4;
	int magic = 56;
	int wew = ok + 5 + 4;
	int wow = magic + 4 + 5;

	short a = (short)fruitCount;
	int treedata = 0x0002000a;

	BYTE* data = new BYTE[packetSize];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	memset(data, 0, packetSize);

	memcpy(data, &packetType, sizeof(int));
	memcpy(data + yeh, &hmm, sizeof(int));
	memcpy(data + yup, &x, sizeof(int));
	memcpy(data + yup + 4, &y, sizeof(int));
	memcpy(data + 4 + yup + 4, &idk, sizeof(int));
	memcpy(data + magic, &foreground, sizeof(short));
	memcpy(data + four + magic, &background, sizeof(int));
	memcpy(data + magic + 4 + four, &bubble_type, sizeof(byte));
	memcpy(data + wow, &text_len, sizeof(short));
	memcpy(data + 2 + wow, &treedata, text_len);
	memcpy(data + ok, &blockState, sizeof(int));
	memcpy(p->data, &four, four);

	memcpy((char*)p->data + four, data, packetSize);
	enet_peer_send(peer, 0, p);

	delete data;
}
void UpdateMessageVisuals(ENetPeer* peer, int foreground, int x, int y, string text, int background, int bubbleType_ = 2, bool sendPacketToEveryone = true, int blockState = 0)
{
	if (text.size() > 100) return;
	// setting tile packet
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

	// hopefully the magic :/
	int hmm = 8, textLen = text.size(), PacketType = 5;
	int yeh = hmm + 3 + 1, idk = 15 + textLen, endMarker = -1, sizeofshort = 2;
	int bubbleType = bubbleType_;
	int ok = 52 + idk;
	int kek = ok + 4, yup = ok - 8 - idk;
	int sizeofint = 4, magic = 56, wew = ok + 5 + 4;
	int wow = magic + 4 + 5;
	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	//MEMCPY DESTINATION					SOURCE			SIZE
	memcpy(data, &PacketType, sizeof(int));
	memcpy(data + yeh, &hmm, sizeof(int));
	memcpy(data + yup, &x, sizeof(int));
	memcpy(data + yup + 4, &y, sizeof(int));
	memcpy(data + 4 + yup + 4, &idk, sizeof(int));
	memcpy(data + magic, &foreground, sizeof(short));
	memcpy(data + magic + 2, &background, sizeof(short));
	memcpy(data + sizeofint + magic, &blockState, sizeof(int));
	memcpy(data + magic + 4 + sizeofint, &bubbleType, sizeof(byte));
	memcpy(data + wow, &textLen, sizeof(short));
	memcpy(data + sizeofshort + wow, text.c_str(), textLen);
	memcpy(data + ok, &endMarker, sizeof(int));
	memcpy(p->data, &sizeofint, sizeof(int));
	memcpy((char*)p->data + sizeofint, data, kek);

	if (sendPacketToEveryone)
	{
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				enet_peer_send(currentPeer, 0, p);
			}
		}
		delete data;
	}
	else
	{
		enet_peer_send(peer, 0, p);
		delete data;
	}
}
void UpdateVisualsForBlock(ENetPeer* peer, bool forEveryone, int x, int y, WorldInfo* worldInfo, bool useLockId = true)
{
	if (!worldInfo) return;

	int i = y * worldInfo->width + x;

	int blockStateFlags = 0;


	if (worldInfo->items[i].flipped)
		blockStateFlags |= 0x00200000;
	if (worldInfo->items[i].water)
		blockStateFlags |= 0x04000000;
	if (worldInfo->items[i].glue)
		blockStateFlags |= 0x08000000;
	if (worldInfo->items[i].fire)
		blockStateFlags |= 0x10000000;
	if (worldInfo->items[i].red)
		blockStateFlags |= 0x20000000;
	if (worldInfo->items[i].green)
		blockStateFlags |= 0x40000000;
	if (worldInfo->items[i].blue)
		blockStateFlags |= 0x80000000;




	else if (getItemDef(worldInfo->items[i].foreground).blockType == BlockTypes::MAIN_DOOR)
	{
		UpdateUnlockedDoorVisuals(peer, worldInfo->items[i].foreground, x, y, worldInfo->items[i].background, "EXIT", forEveryone, blockStateFlags);
	}

	else if (worldInfo->items[i].foreground == 2946)
	{

		UpdateDisplayVisuals(peer, worldInfo->items[i].foreground, x, y, worldInfo->items[i].background, worldInfo->items[i].intdata);
	}
	else if (worldInfo->items[i].foreground % 2 == 1)
	{
		UpdateTreeVisuals(peer, worldInfo->items[i].foreground, x, y, worldInfo->items[i].background, 3);
	}
	else if (blockStateFlags != 0)
	{
		UpdateMessageVisuals(peer, worldInfo->items[i].foreground, x, y, "", worldInfo->items[i].background, 0, forEveryone, blockStateFlags);
	}
}
void updateVendMsg(ENetPeer* peer, int foreground, int x, int y, string text)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	int hmm = 8;
	int text_len = text.length();
	int lol = 0;
	int wut = 5;
	int yeh = hmm + 3 + 1;
	int idk = 15 + text_len;
	int is_locked = 0;
	int bubble_type = 21;
	int ok = 52 + idk;
	int kek = ok + 4;
	int yup = ok - 8 - idk;
	int four = 4;
	int magic = 56;
	int wew = ok + 5 + 4;
	int wow = magic + 4 + 5;

	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, four);
	memcpy(data + yeh, &hmm, four);
	memcpy(data + yup, &x, 4);
	memcpy(data + yup + 4, &y, 4);
	memcpy(data + 4 + yup + 4, &idk, four);
	memcpy(data + magic, &foreground, 2);
	memcpy(data + four + magic, &lol, four);
	memcpy(data + magic + 4 + four, &bubble_type, 1);
	memcpy(data + wow, &text_len, 2);
	memcpy(data + 2 + wow, text.c_str(), text_len);
	memcpy(data + ok, &is_locked, four);
	memcpy(p->data, &four, four);
	memcpy((char*)p->data + four, data, kek);
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			enet_peer_send(currentPeer, 0, p);
		}
	}
	delete data;
}
void UpdateBlockState(ENetPeer* peer, int x, int y, bool forEveryone, WorldInfo* worldInfo) {

	if (!worldInfo) return;

	int i = y * worldInfo->width + x;

	int blockStateFlags = 0;


	if (worldInfo->items[i].flipped)
		blockStateFlags |= 0x00200000;
	if (worldInfo->items[i].water)
		blockStateFlags |= 0x04000000;
	if (worldInfo->items[i].glue)
		blockStateFlags |= 0x08000000;
	if (worldInfo->items[i].fire)
		blockStateFlags |= 0x10000000;
	if (worldInfo->items[i].red)
		blockStateFlags |= 0x20000000;
	if (worldInfo->items[i].green)
		blockStateFlags |= 0x40000000;
	if (worldInfo->items[i].blue)
		blockStateFlags |= 0x80000000;
	if (worldInfo->items[i].active)
		blockStateFlags |= 0x00400000;
	if (worldInfo->items[i].silenced)
		blockStateFlags |= 0x02400000;

	if (worldInfo->items[i].foreground == 5638)
	{
		if (worldInfo->magplant == true) {
			sendMag(peer, x, y, 112, 1, true, true);
		}

	}
}


void playerRespawn(ENetPeer* peer, bool isDeadByTile) {
	int netID = ((PlayerInfo*)(peer->data))->netID;
	if (isDeadByTile == false) {
		Player::OnKilled(peer, ((PlayerInfo*)(peer->data))->netID);
	}
	GamePacket p2x = packetEnd(appendInt(appendString(createPacket(), "OnSetFreezeState"), 0));
	memcpy(p2x.data + 8, &netID, 4);
	int respawnTimeout = 2000;
	int deathFlag = 0x19;
	memcpy(p2x.data + 24, &respawnTimeout, 4);
	memcpy(p2x.data + 56, &deathFlag, 4);
	ENetPacket* packet2x = enet_packet_create(p2x.data,
		p2x.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2x);
	delete p2x.data;
	GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetFreezeState"), 2));
	memcpy(p5.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
	ENetPacket* packet5 = enet_packet_create(p5.data,
		p5.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet5);	
	GamePacket p2;
	WorldInfo* world = getPlyersWorld(peer);
	int x = 3040;
	int y = 736;

	if (!world) return;

	for (int i = 0; i < world->width * world->height; i++)
	{
		if (world->items[i].foreground == 6) {
			x = (i % world->width) * 32;
			y = (i / world->width) * 32;
		}
	}
	if (((PlayerInfo*)(peer->data))->ischeck == true) {
		p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), ((PlayerInfo*)(peer->data))->checkx, ((PlayerInfo*)(peer->data))->checky));
	}
	else {
		p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x, y));
	}
	memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
	respawnTimeout = 2000;
	memcpy(p2.data + 24, &respawnTimeout, 4);
	memcpy(p2.data + 56, &deathFlag, 4);
	ENetPacket* packet2 = enet_packet_create(p2.data,
		p2.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2);
	delete p2.data;
	GamePacket p2a = packetEnd(appendString(appendString(createPacket(), "OnPlayPositioned"), "audio/teleport.wav"));
	memcpy(p2a.data + 8, &netID, 4);
	respawnTimeout = 2000;
	memcpy(p2a.data + 24, &respawnTimeout, 4);
	memcpy(p2a.data + 56, &deathFlag, 4);
	ENetPacket* packet2a = enet_packet_create(p2a.data,
		p2a.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2a);
	delete p2a.data;
}
void InitializePacketWithMannequin(BYTE* raw)
{
	int i = 0;
	raw[i] = 0x05; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x08; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x09; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x17; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x22; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x8c; i++;
	raw[i] = 0x05; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x01; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x0e; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
	raw[i] = 0x00; i++;
}

struct TileExtra {
	int packetType;
	int characterState;
	float objectSpeedX;
	int punchX;
	int punchY;
	int charStat;
	int blockid;
	int visual;
	int signs;
	int backgroundid;
	int displayblock;
	int time;
	int netID;
	int weatherspeed;
	int bpm;
	int unused1;
	int unused2;
	int unused3;
	//int bpm;
};
BYTE* packBlockVisual222(TileExtra* dataStruct)
{

	BYTE* data = new BYTE[104]; // 96
	for (int i = 0; i < 100; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 8, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 16, &dataStruct->objectSpeedX, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	memcpy(data + 52, &dataStruct->charStat, 4);
	memcpy(data + 56, &dataStruct->blockid, 2);
	memcpy(data + 58, &dataStruct->backgroundid, 2);
	memcpy(data + 60, &dataStruct->visual, 4);
	memcpy(data + 64, &dataStruct->displayblock, 4);


	return data;
}
BYTE* packStuffVisual(TileExtra* dataStruct, int options, int gravity)
{
	BYTE* data = new BYTE[102];
	for (int i = 0; i < 102; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 8, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	memcpy(data + 52, &dataStruct->charStat, 4);
	memcpy(data + 56, &dataStruct->blockid, 2);
	memcpy(data + 58, &dataStruct->backgroundid, 2);
	memcpy(data + 60, &dataStruct->visual, 4);
	memcpy(data + 64, &dataStruct->displayblock, 4);
	memcpy(data + 68, &gravity, 4);
	memcpy(data + 70, &options, 4);

	return data;
}

void updateMannequin(
	ENetPeer* peer, int foreground, int x, int y, int background, string text,
	int clothHair, int clothHead, int clothMask,
	int clothHand, int clothNeck, int clothShirt,
	int clothPants, int clothFeet, int clothBack, bool sendPacketToEveryone = true, int blockState = 0)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

	short textLen = text.size();
	int plength = 95 + textLen;
	BYTE* raw = new BYTE[plength];
	memset(raw, 0, plength);
	InitializePacketWithMannequin(raw);
	int negativeOne = -1;
	int adjhasdjk = 0xfdfdfdfd;
	int visor = 138;

	memcpy(raw + 44, &x, sizeof(int));
	memcpy(raw + 48, &y, sizeof(int));
	memcpy(raw + 56, &foreground, sizeof(short));
	memcpy(raw + 58, &background, sizeof(short));
	memcpy(raw + 60, &blockState, sizeof(short));
	memcpy(raw + 65, &textLen, sizeof(short));
	memcpy(raw + 67, text.c_str(), textLen);
	memcpy(raw + 68 + textLen, &negativeOne, sizeof(int));
	memcpy(raw + 72 + textLen, &clothHead, sizeof(short));
	memcpy(raw + 74 + textLen, &clothShirt, sizeof(short));
	memcpy(raw + 76 + textLen, &clothPants, sizeof(short));
	memcpy(raw + 78 + textLen, &clothFeet, sizeof(short));
	memcpy(raw + 80 + textLen, &clothMask, sizeof(short));
	memcpy(raw + 82 + textLen, &clothHand, sizeof(short));
	memcpy(raw + 84 + textLen, &clothBack, sizeof(short));
	memcpy(raw + 86 + textLen, &clothHair, sizeof(short));
	memcpy(raw + 88 + textLen, &clothNeck, sizeof(short));
	memcpy(raw + 91 + textLen, &adjhasdjk, sizeof(short));

	ENetPacket* p = enet_packet_create(0, plength + 4, ENET_PACKET_FLAG_RELIABLE);
	int four = 4;
	memcpy(p->data, &four, sizeof(int));
	memcpy((char*)p->data + 4, raw, plength);

	if (sendPacketToEveryone)
	{
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				enet_peer_send(currentPeer, 0, p);
			}
		}
		delete raw;
	}
	else
	{
		enet_peer_send(peer, 0, p);
		delete raw;
	}
}
void updateStuffWeather(ENetPeer* peer, int x, int y, int tile, int bg, int gravity, bool isInverted, bool isSpinning) {


	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {




			//cout << "[!] bruh" << endl;
			TileExtra data;
			data.packetType = 0x5;
			data.characterState = 8;
			data.punchX = x;
			data.punchY = y;
			data.charStat = 18; // 13
			data.blockid = 3832;
			data.backgroundid = bg; // 2946
								   //data.netID = ((PlayerInfo)(peer->data))->netID;
								   //dataxx.backgroundid = 65536;
			data.visual = 0; //0x00210000
										//world->items[x + (yworld->width)].displayblock = tile;
			int n = tile;
			string hex = "";
			{
				std::stringstream ss;
				ss << std::hex << n; // int decimal_value
				std::string res(ss.str());
				hex = res + "31";
			}
			int gravi = gravity;
			string hexg = "";
			{
				int temp = gravi;
				if (gravi < 0) temp = -gravi;
				std::stringstream ss;
				ss << std::hex << temp; // int decimal_value
				std::string res(ss.str());
				hexg = res + "00";
			}
			int xx = 0;
			std::stringstream ss;
			ss << std::hex << hex;
			if (!ss.fail()) {
				ss >> xx;
			}
			//cout << xx << endl;
			data.displayblock = xx;
			int xxs = 0;
			std::stringstream sss;
			sss << std::hex << hexg;
			if (!sss.fail()) {
				sss >> xxs;
			}
			if (gravi < 0) xxs = -xxs;
			//cout << to_string(xxs) << endl;
			if (gravi < 0) {
				SendPacketRaw(192, packStuffVisual(&data, 0x03FFFFFF, xxs), 102, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
			else
			{
				SendPacketRaw(192, packStuffVisual(&data, 0x02000000, xxs), 102, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
			GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), 29));
			ENetPacket* packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2);
			delete p2.data;
		}
	}
}
void updateSign(ENetPeer* peer, int foreground, int x, int y, string text, int background)
{
	PlayerMoving sign;
	sign.packetType = 0x3;
	sign.characterState = 0x0;
	sign.x = x;
	sign.y = y;
	sign.punchX = x;
	sign.punchY = y;
	sign.XSpeed = 0;
	sign.YSpeed = 0;
	sign.netID = -1;
	sign.plantingTree = foreground;
	SendPacketRaw(4, packPlayerMoving(&sign), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	int hmm = 8, wot = text.length(), lol = 0, wut = 5;
	int yeh = hmm + 3 + 1, idk = 15 + wot, lmao = -1, yey = 2; //idk = text_len + 15, wut = type(?), wot = text_len, yey = len of text_len
	int ok = 52 + idk;
	int kek = ok + 4, yup = ok - 8 - idk;
	int thonk = 4, magic = 56, wew = ok + 5 + 4;
	int wow = magic + 4 + 5;
	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, thonk);
	memcpy(data + yeh, &hmm, thonk); //read discord
	memcpy(data + yup, &x, 4);
	memcpy(data + yup + 4, &y, 4);
	memcpy(data + 4 + yup + 4, &idk, thonk);
	memcpy(data + magic, &foreground, yey);
	memcpy(data + magic + 2, &background, yey); //p100 fix by the one and only lapada
	memcpy(data + thonk + magic, &lol, thonk);
	memcpy(data + magic + 4 + thonk, &yey, 1);
	memcpy(data + wow, &wot, yey); //data + wow = text_len
	memcpy(data + yey + wow, text.c_str(), wot); //data + text_len_len + text_len_offs = text
	memcpy(data + ok, &lmao, thonk); //end ?
	memcpy(p->data, &thonk, thonk);
	memcpy((char*)p->data + thonk, data, kek); //kek = data_len
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			enet_peer_send(currentPeer, 0, p);
		}
	}
	delete data;
}


void updateSignSound(ENetPeer* peer, int foreground, int x, int y, string text, int background)
{
	int hmm = 8, wot = text.length(), lol = 0, wut = 5;
	int yeh = hmm + 3 + 1, idk = 15 + wot, lmao = -1, yey = 2; //idk = text_len + 15, wut = type(?), wot = text_len, yey = len of text_len
	int ok = 52 + idk;
	int kek = ok + 4, yup = ok - 8 - idk;
	int thonk = 4, magic = 56, wew = ok + 5 + 4;
	int wow = magic + 4 + 5;
	BYTE* data = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) data[i] = 0;
	memcpy(data, &wut, thonk);
	memcpy(data + yeh, &hmm, thonk); //read discord
	memcpy(data + yup, &x, 4);
	memcpy(data + yup + 4, &y, 4);
	memcpy(data + 4 + yup + 4, &idk, thonk);
	memcpy(data + magic, &foreground, yey);
	memcpy(data + magic + 2, &background, yey); //p100 fix by the one and only lapada
	memcpy(data + thonk + magic, &lol, thonk);
	memcpy(data + magic + 4 + thonk, &yey, 1);
	memcpy(data + wow, &wot, yey); //data + wow = text_len
	memcpy(data + yey + wow, text.c_str(), wot); //data + text_len_len + text_len_offs = text
	memcpy(data + ok, &lmao, thonk); //end ?
	memcpy(p->data, &thonk, thonk);
	memcpy((char*)p->data + thonk, data, kek); //kek = data_len
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			enet_peer_send(currentPeer, 0, p);
		}
	}
	delete data;
}

void updateAllClothes(ENetPeer* peer)
{
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			GamePacket p3 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants), ((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand), ((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace), ((PlayerInfo*)(peer->data))->skinColor), ((PlayerInfo*)(peer->data))->cloth_ances, 0.0f, 0.0f));
			memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
			ENetPacket* packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet3);
			delete p3.data;
			//enet_host_flush(server);
			GamePacket p4 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(currentPeer->data))->cloth_hair, ((PlayerInfo*)(currentPeer->data))->cloth_shirt, ((PlayerInfo*)(currentPeer->data))->cloth_pants), ((PlayerInfo*)(currentPeer->data))->cloth_feet, ((PlayerInfo*)(currentPeer->data))->cloth_face, ((PlayerInfo*)(currentPeer->data))->cloth_hand), ((PlayerInfo*)(currentPeer->data))->cloth_back, ((PlayerInfo*)(currentPeer->data))->cloth_mask, ((PlayerInfo*)(currentPeer->data))->cloth_necklace), ((PlayerInfo*)(currentPeer->data))->skinColor), ((PlayerInfo*)(currentPeer->data))->cloth_ances, 0.0f, 0.0f));
			memcpy(p4.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4); // ffloor
			ENetPacket* packet4 = enet_packet_create(p4.data,
				p4.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet4);
			delete p4.data;
			//enet_host_flush(server);
		}
	}
}

void sendTime(ENetPeer* peer)
{
	time_t _tm = time(NULL);
	struct tm* curtime = localtime(&_tm);
	string test = asctime(curtime);
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `2Current time is: " + test));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);

	//enet_host_flush(server);
	delete p.data;
}

void sendClothes(ENetPeer* peer)
{
	ENetPeer* currentPeer;
	GamePacket p3 = packetEnd(appendFloat(appendIntx(appendFloat(appendFloat(appendFloat(appendString(createPacket(), "OnSetClothing"), ((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants), ((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand), ((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace), ((PlayerInfo*)(peer->data))->skinColor), ((PlayerInfo*)(peer->data))->cloth_ances, 0.0f, 0.0f));
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			string text = "action|play_sfx\nfile|audio/change_clothes.wav\ndelayMS|0\n";
			BYTE* data = new BYTE[5 + text.length()];
			BYTE zero = 0;
			int type = 3;
			memcpy(data, &type, 4);
			memcpy(data + 4, text.c_str(), text.length());
			memcpy(data + 4 + text.length(), &zero, 1);

			ENetPacket* packet2 = enet_packet_create(data,
				5 + text.length(),
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2);
			delete data;


			//enet_host_flush(server);

			memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor
			ENetPacket* packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet3);
		}

	}
		std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");

		PlayerInfo* p = ((PlayerInfo*)(peer->data));

		string username = PlayerDB::getProperName(p->rawName);



		if (ifff.fail()) {
			ifff.close();


		}
		if (ifff.is_open()) {
		}
		json j;
		ifff >> j; //load

		int gems = p->gem;
		int rubble = p->ban;
		int wls = p->wls;
		int clothback = p->cloth_back;
		int clothhand = p->cloth_hand;
		int clothface = p->cloth_face;
		int clothhair = p->cloth_hair;
		int clothfeet = p->cloth_feet;
		int clothpants = p->cloth_pants;
		int clothneck = p->cloth_necklace;
		int clothshirt = p->cloth_shirt;
		int clothmask = p->cloth_mask;
		int clothances = p->cloth_ances;

		j["ClothBack"] = clothback;
		j["ClothHand"] = clothhand;
		j["ClothFace"] = clothface;
		j["ClothShirt"] = clothshirt;
		j["ClothPants"] = clothpants;
		j["ClothNeck"] = clothneck;
		j["ClothHair"] = clothhair;
		j["ClothFeet"] = clothfeet;
		j["ClothMask"] = clothmask;
		j["ClothAnces"] = clothances;
		j["puncheffect"] = p->peffect;
		j["gems"] = gems;
		j["ban"] = rubble;
		j["wls"] = wls;


		//j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;


		std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
		if (!o.is_open()) {
			cout << GetLastError() << endl;
			_getch();
		}

		o << j << std::endl;
}
void SendGamePacket(ENetPeer* peer, GamePacket* p)
{
	ENetPacket* packet1 = enet_packet_create(p->data,
		p->len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet1);
}
void sendSound(ENetPeer* peer, string sound)
{
	string text = "action|play_sfx\nfile|audio/" + sound + "\ndelayMS|0\n";
	BYTE* data = new BYTE[5 + text.length()];
	BYTE zero = 0;
	int type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);

	ENetPacket * packet2 = enet_packet_create(data,
		5 + text.length(),
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet2);
	delete data;
}
void sendPData(ENetPeer* peer, PlayerMoving* data)
{
	ENetPeer* currentPeer;

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (peer != currentPeer)
		{
			if (isHere(peer, currentPeer))
			{
				data->netID = ((PlayerInfo*)(peer->data))->netID;

				SendPacketRaw(4, packPlayerMoving(data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}
}

int getPlayersCountInWorld(string name)
{
	int count = 0;
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (((PlayerInfo*)(currentPeer->data))->currentWorld == name)
			count++;
	}
	return count;
}


void sendRoulete(ENetPeer* peer)
{
	using namespace std::chrono;




	if (((PlayerInfo*)(peer->data))->lastSPIN + 1500 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
	{
		((PlayerInfo*)(peer->data))->lastSPIN = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
	}


	else {

		return;

	}
	ENetPeer* currentPeer;
	int val = rand() % 36;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			string name = ((PlayerInfo*)(peer->data))->displayName;
			/*
			if (((PlayerInfo*)(peer->data))->lastSpin + 1500 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
			{
			((PlayerInfo*)(peer->data))->lastSpin = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
			}


			else {
			GamePacket po = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`4Please spin slow!"));
			ENetPacket * packet = enet_packet_create(po.data,
			po.len,
			ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete po.data;
			//enet_host_flush(server);
			continue;
			}*/

			if (val == 1 || val == 3 || val == 5 || val == 7 || val == 9 || val == 12 || val == 14 || val == 16 || val == 18 || val == 19 || val == 21 || val == 23 || val == 25 || val == 27 || val == 30 || val == 32 || val == 34 || val == 36) {
				if (((PlayerInfo*)(peer->data))->rawName == "mindpin") {
					GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`w[" + name + " `wspun the wheel and got `436`w!]"), 0));
					int respawnTimeout = 2000;
					int deathFlag = 0x19;
					memcpy(p2.data + 24, &respawnTimeout, 4);
					memcpy(p2.data + 56, &deathFlag, 4);
					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);
					delete p2.data;
					GamePacket p2s = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `7[`w" + name + " `ospun the wheel and got `436`o!`7]"));

					memcpy(p2s.data + 24, &respawnTimeout, 4);
					memcpy(p2s.data + 56, &deathFlag, 4);
					ENetPacket* packet2s = enet_packet_create(p2s.data,
						p2s.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2s);
					delete p2s.data;
				}
				else {
					GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`w[" + name + " `wspun the wheel and got `4" + std::to_string(val) + "`w!]"), 0));
					int respawnTimeout = 2000;
					int deathFlag = 0x19;
					memcpy(p2.data + 24, &respawnTimeout, 4);
					memcpy(p2.data + 56, &deathFlag, 4);
					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);
					delete p2.data;
					GamePacket p2s = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `7[`w" + name + " `ospun the wheel and got `4" + std::to_string(val) + "`o!`7]"));

					memcpy(p2s.data + 24, &respawnTimeout, 4);
					memcpy(p2s.data + 56, &deathFlag, 4);
					ENetPacket* packet2s = enet_packet_create(p2s.data,
						p2s.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2s);
					delete p2s.data;
				}
			}
			else if (val == 2 || val == 4 || val == 6 || val == 8 || val == 10 || val == 11 || val == 13 || val == 15 || val == 17 || val == 20 || val == 22 || val == 24 || val == 26 || val == 28 || val == 29 || val == 31 || val == 33 || val == 35) {
				if (((PlayerInfo*)(peer->data))->rawName == "mindpin") {
					GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`w[" + name + " `wspun the wheel and got `b35`w!]"), 0));
					int respawnTimeout = 2000;
					int deathFlag = 0x19;
					memcpy(p2.data + 24, &respawnTimeout, 4);
					memcpy(p2.data + 56, &deathFlag, 4);
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);

					delete p2.data;
					GamePacket p2s = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `7[`w" + name + " `ospun the wheel and got `b35`o!`7]"));

					memcpy(p2s.data + 24, &respawnTimeout, 4);
					memcpy(p2s.data + 56, &deathFlag, 4);
					ENetPacket* packet2s = enet_packet_create(p2s.data,
						p2s.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2s);
					delete p2s.data;
				}
				else {
					GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`w[" + name + " `wspun the wheel and got `b" + std::to_string(val) + "`w!]"), 0));
					int respawnTimeout = 2000;
					int deathFlag = 0x19;
					memcpy(p2.data + 24, &respawnTimeout, 4);
					memcpy(p2.data + 56, &deathFlag, 4);
					ENetPacket * packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);

					delete p2.data;
					GamePacket p2s = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `7[`w" + name + " `ospun the wheel and got `b" + std::to_string(val) + "`o!`7]"));

					memcpy(p2s.data + 24, &respawnTimeout, 4);
					memcpy(p2s.data + 56, &deathFlag, 4);
					ENetPacket* packet2s = enet_packet_create(p2s.data,
						p2s.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2s);
					delete p2s.data;
				}

			}

			else if (val == 0 || val == 37) {

				GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`w[" + name + " `wspun the wheel and got `20`w!]"), 0));
				int respawnTimeout = 2000;
				int deathFlag = 0x19;
				memcpy(p2.data + 24, &respawnTimeout, 4);
				memcpy(p2.data + 56, &deathFlag, 4);
				ENetPacket* packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);
				delete p2.data;
				GamePacket p2s = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `7[`w" + name + " `ospun the wheel and got `20`o!`7]"));

				memcpy(p2s.data + 24, &respawnTimeout, 4);
				memcpy(p2s.data + 56, &deathFlag, 4);
				ENetPacket* packet2s = enet_packet_create(p2s.data,
					p2s.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2s);
				delete p2s.data;
			}
		}

	}
}

void sendNothingHappened(ENetPeer* peer, int x, int y) {
	PlayerMoving data;
	data.netID = ((PlayerInfo*)(peer->data))->netID;
	data.packetType = 0x8;
	data.plantingTree = 0;
	data.netID = -1;
	data.x = x;
	data.y = y;
	data.punchX = x;
	data.punchY = y;
	SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
}
void SendTilePickup(ENetPeer* peer, int itemid, int netID, float x, float y, int itemcount, int itemamount) {
	PlayerMoving data;
	data.characterState = 0x0; // animation
	data.x = x * 32;
	data.y = y * 32;
	data.punchX = 0;
	data.punchY = 0;
	data.XSpeed = 0;
	data.YSpeed = 0;
	data.netID = -1;
	data.secondnetID = -1;
	data.plantingTree = itemid;
	data.packetType = 0xE;
	BYTE* raw = packPlayerMoving(&data);
	int netIdSrc = -1;
	int netIdDst = -1;
	int three = 3;
	int n1 = itemid;
	int one = 1;
	float count = itemamount;
	memcpy(raw + 3, &three, 1);
	memcpy(raw + 4, &netIdDst, 4);
	memcpy(raw + 8, &netIdSrc, 4);
	memcpy(raw + 16, &count, 4);
	memcpy(raw + 20, &n1, 4);

	((PlayerInfo*)(peer->data))->droppeditemcount++;
	SendPacketRaw(4, raw, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

	PlayerMoving datax;
	datax.characterState = 0x0; // animation
	datax.x = x * 32;
	datax.y = y * 32;
	datax.punchX = 0;
	datax.punchY = 0;
	datax.XSpeed = 0;
	datax.YSpeed = 0;
	datax.netID = -1;
	datax.secondnetID = 0;
	datax.plantingTree = itemid;
	datax.packetType = 0xE;
	BYTE* raws = packPlayerMoving(&data);
	int lol = -1;


	memcpy(raws + 3, &three, 1);
	memcpy(raws + 4, &netID, 4);
	memcpy(raws + 8, &lol, 4);
	memcpy(raws + 20, &((PlayerInfo*)(peer->data))->droppeditemcount, 4);
	SendPacketRaw(4, raws, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
}
void sendState(ENetPeer* peer) {
	//return; // TODO
	PlayerInfo* info = ((PlayerInfo*)(peer->data));
	int netID = info->netID;
	ENetPeer* currentPeer;
	int state = getState(info);
	int pro = getCharstat(info);
	int statey = 0;
	if (info->cloth_hand == 6028) statey = 1024;
	if (info->cloth_hand == 6262) statey = 8192;
	if (info->haveGrowId == false) statey = 50000;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			PlayerMoving data;
			data.packetType = 0x14;
			data.characterState = statey;
			data.x = 1000;
			data.y = 100;
			data.punchX = 0;
			data.punchY = 0;
			data.XSpeed = 300;
			data.YSpeed = 600;
			data.netID = netID;
			data.plantingTree = state;
			BYTE* raw = packPlayerMoving(&data);
			int var = info->peffect; // punch effect
			memcpy(raw + 1, &var, 3);
			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
	// TODO
}

void sendWorld(ENetPeer* peer, WorldInfo* worldInfo)
{

	// LOADING DROPPED ITEMS
	/*DroppedItem itemDropped;
	itemDropped.id = 0;
	itemDropped.count = 0;
	itemDropped.x = 0;
	itemDropped.y = 0;
	itemDropped.uid = 0;*/
	// TODO DROPPING ITEMS!!!!!!!!!!!!!!!!
	/*if (worldInfo->dropSized == false) {
		worldInfo->droppedItems.resize(1024000);
		for (int i = 0; i < 65536; i++) worldInfo->droppedItems.push_back(itemDropped);
		worldInfo->dropSized = true;
	}*/


	int zero = 0;
	((PlayerInfo*)(peer->data))->droppeditemcount = 0;
#ifdef TOTAL_LOG
	cout << "[!] Entering a world..." << endl;
#endif
	((PlayerInfo*)(peer->data))->joinClothesUpdated = false;
	string asdf = "0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000070000000000"; // 0400000004A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000080000000000000000000000000000000000000000000000000000000000000048133A0500000000BEBB0000070000000000
	string worldName = worldInfo->name;
	int xSize = worldInfo->width;
	int ySize = worldInfo->height;
	int square = xSize * ySize;
	__int16 nameLen = (__int16)worldName.length();
	int payloadLen = asdf.length() / 2;
	int dataLen = payloadLen + 2 + nameLen + 12 + (square * 8) + 4 + 100;
	int offsetData = dataLen - 100;
	int allocMem = payloadLen + 2 + nameLen + 12 + (square * 8) + 4 + 16000 + 100 + (worldInfo->droppedCount * 20);
	BYTE* data = new BYTE[allocMem];
	memset(data, 0, allocMem);
	for (int i = 0; i < asdf.length(); i += 2)
	{
		char x = ch2n(asdf[i]);
		x = x << 4;
		x += ch2n(asdf[i + 1]);
		memcpy(data + (i / 2), &x, 1);
	}

	__int16 item = 0;
	int smth = 0;
	for (int i = 0; i < square * 8; i += 4) memcpy(data + payloadLen + i + 14 + nameLen, &zero, 4);
	for (int i = 0; i < square * 8; i += 8) memcpy(data + payloadLen + i + 14 + nameLen, &item, 2);
	memcpy(data + payloadLen, &nameLen, 2);
	memcpy(data + payloadLen + 2, worldName.c_str(), nameLen);
	memcpy(data + payloadLen + 2 + nameLen, &xSize, 4);
	memcpy(data + payloadLen + 6 + nameLen, &ySize, 4);
	memcpy(data + payloadLen + 10 + nameLen, &square, 4);
	BYTE* blockPtr = data + payloadLen + 14 + nameLen;

	int sizeofblockstruct = 8;


	for (int i = 0; i < square; i++) {

		int tile = worldInfo->items[i].foreground;
		sizeofblockstruct = 8;


		//if (world->items[x + (y*world->width)].foreground == 242 or world->items[x + (y*world->width)].foreground == 2408 or world->items[x + (y*world->width)].foreground == 5980 or world->items[x + (y*world->width)].foreground == 2950 or world->items[x + (y*world->width)].foreground == 5814 or world->items[x + (y*world->width)].foreground == 4428 or world->items[x + (y*world->width)].foreground == 1796 or world->items[x + (y*world->width)].foreground == 4802 or world->items[x + (y*world->width)].foreground == 4994 or world->items[x + (y*world->width)].foreground == 5260 or world->items[x + (y*world->width)].foreground == 7188)
		if (tile == 6) {
			int type = 0x00010000;
			memcpy(blockPtr, &tile, 2);
			memcpy(blockPtr + 4, &type, 4);
			BYTE btype = 1;
			memcpy(blockPtr + 8, &btype, 1);

			string doorText = "EXIT";
			const char* doorTextChars = doorText.c_str();
			short length = (short)doorText.size();
			memcpy(blockPtr + 9, &length, 2);
			memcpy(blockPtr + 11, doorTextChars, length);
			sizeofblockstruct += 4 + length;
			dataLen += 4 + length; // it's already 8.

		}
		else if (getItemDef(tile).blockType == BlockTypes::SIGN || tile == 1420 || tile == 6124) {
			int type = 0x00010000;
			memcpy(blockPtr, &worldInfo->items[i].foreground, 2);
			memcpy(blockPtr + 4, &type, 4);
			BYTE btype = 2;
			memcpy(blockPtr + 8, &btype, 1);
			string signText = worldInfo->items[i].text;
			const char* signTextChars = signText.c_str();
			short length = (short)signText.size();
			memcpy(blockPtr + 9, &length, 2);
			memcpy(blockPtr + 11, signTextChars, length);
			int minus1 = -1;
			memcpy(blockPtr + 11 + length, &minus1, 4);
			sizeofblockstruct += 3 + length + 4;
			dataLen += 3 + length + 4; // it's already 8.
		}
		else if ((worldInfo->items[i].foreground == 0) || (worldInfo->items[i].foreground == 2) || (worldInfo->items[i].foreground == 8) || (worldInfo->items[i].foreground == 100) || (worldInfo->items[i].foreground == 4))
		{

			memcpy(blockPtr, &worldInfo->items[i].foreground, 2);
			int type = 0x00000000;

			// type 1 = locked
			if (worldInfo->items[i].activated)
				type |= 0x00200000;
			if (worldInfo->items[i].water)
				type |= 0x04000000;
			if (worldInfo->items[i].glue)
				type |= 0x08000000;
			if (worldInfo->items[i].fire)
				type |= 0x10000000;
			if (worldInfo->items[i].red)
				type |= 0x20000000;
			if (worldInfo->items[i].green)
				type |= 0x40000000;
			if (worldInfo->items[i].blue)
				type |= 0x80000000;

			// int type = 0x04000000; = water
			// int type = 0x08000000 = glue
			// int type = 0x10000000; = fire
			// int type = 0x20000000; = red color
			// int type = 0x40000000; = green color
			// int type = 0x80000000; = blue color


			memcpy(blockPtr + 4, &type, 4);
			/*if (worldInfo->items[i].foreground % 2)
			{
				blockPtr += 6;
			}*/
		}
		else
		{
			memcpy(blockPtr, &zero, 2);
		}
		memcpy(blockPtr + 2, &worldInfo->items[i].background, 2);
		blockPtr += sizeofblockstruct;


	}

	/*int increase = 20;
//TODO

	int inc = 20;
	memcpy(blockPtr, &worldInfo->droppedCount, 4);
	memcpy(blockPtr + 4, &worldInfo->droppedCount, 4);

	for (int i = 0; i < worldInfo->droppedCount; i++) {

		memcpy(blockPtr + inc - 12, &worldInfo->droppedItems.at(i).id, 2);
		memcpy(blockPtr + inc - 10, &worldInfo->droppedItems.at(i).x, 4);
		memcpy(blockPtr + inc - 6, &worldInfo->droppedItems.at(i).y, 4);
		memcpy(blockPtr + inc - 2, &worldInfo->droppedItems.at(i).count, 2);
		memcpy(blockPtr + inc, &i, 4);
		inc += 16;

	}
	blockPtr += inc;
	dataLen += inc;*/

	//((PlayerInfo*)(peer->data))->droppeditemcount = worldInfo->droppedCount;
	offsetData = dataLen - 100;

	//              0       1       2       3       4       5       6       7       8       9      10     11      12      13      14
	string asdf2 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	BYTE* data2 = new BYTE[101];
	memcpy(data2 + 0, &zero, 4);
	for (int i = 0; i < asdf2.length(); i += 2)
	{
		char x = ch2n(asdf2[i]);
		x = x << 4;
		x += ch2n(asdf2[i + 1]);
		memcpy(data2 + (i / 2), &x, 1);
	}
	int weather = worldInfo->weather;
	memcpy(data2 + 4, &weather, 4);

	memcpy(data + offsetData, data2, 100);


	//cout << dataLen << " <- dataLen allocMem -> " << allocMem << endl;
	memcpy(data + dataLen - 4, &smth, 4);
	ENetPacket * packet2 = enet_packet_create(data,
		dataLen,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2);
	//enet_host_flush(server);
	for (int i = 0; i < square; i++) {
		ItemDefinition pro;
		pro = getItemDef(worldInfo->items[i].foreground);
		if ((worldInfo->items[i].foreground == 0) || (getItemDef(worldInfo->items[i].foreground).blockType) == BlockTypes::SIGN || worldInfo->items[i].foreground == 1420 || worldInfo->items[i].foreground == 6214 || (worldInfo->items[i].foreground == 3832) || (worldInfo->items[i].foreground == 2946) || (worldInfo->items[i].foreground == 6) || (worldInfo->items[i].foreground == 4) || (worldInfo->items[i].foreground == 2) || (worldInfo->items[i].foreground == 8) || (worldInfo->items[i].foreground == 100))
			; // nothing
		else if (worldInfo->items[i].foreground == 242 || worldInfo->items[i].foreground == 2408 || worldInfo->items[i].foreground == 1796 || worldInfo->items[i].foreground == 4428 || worldInfo->items[i].foreground == 7188)
		{
			ENetPeer* currentPeer;

			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer)) {
					int x = i % xSize, y = i / xSize;
					sendTileData(currentPeer, x, y, 0x10, worldInfo->items[x + (y*worldInfo->width)].foreground, worldInfo->items[x + (y*worldInfo->width)].background, lockTileDatas(0x20, worldInfo->ownerID, 0, 0, false, 100));
				}
			}
		}
		else
		{
			PlayerMoving data;
			//data.packetType = 0x14;
			data.packetType = 0x3;

			//data.characterState = 0x924; // animation
			data.characterState = 0x0; // animation
			data.x = i % worldInfo->width;
			data.y = i / worldInfo->height;
			data.punchX = i % worldInfo->width;
			data.punchY = i / worldInfo->width;
			data.XSpeed = 0;
			data.YSpeed = 0;
			data.netID = -1;
			data.plantingTree = worldInfo->items[i].foreground;
			SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
			int x = i % xSize, y = i / xSize;
			UpdateBlockState(peer, x, y, true, worldInfo);
		}
	}
	int idx = 0;
	for (int i = 0; i < worldInfo->droppedItemUid; i++)
	{
		bool found = false;
		for (int j = 0; j < worldInfo->droppedItems.size(); j++)
		{
			if (worldInfo->droppedItems.at(j).uid == i)
			{
				SendDropSingle(peer, -1, worldInfo->droppedItems.at(j).x, worldInfo->droppedItems.at(j).y, worldInfo->droppedItems.at(j).id, worldInfo->droppedItems.at(j).count, 0);
				found = true;
				break;
			}
		}
		// temporary fix
		if (!found) SendDropSingle(peer, -1, -1000, -1000, 0, 1, 0);
	}
	((PlayerInfo*)(peer->data))->currentWorld = worldInfo->name;
	for (int i = 0; i < xSize; i++) {
		for (int j = 0; j < ySize; j++) {
			int squaresign = i + (j * 100);

			bool displaysss = std::experimental::filesystem::exists("display/" + worldInfo->name + "X" + std::to_string(squaresign) + ".txt");

			if (displaysss) {
				if (worldInfo->items[squaresign].foreground == 2946)
				{

					int x = squaresign % worldInfo->width;
					int y = squaresign / worldInfo->width;
					//cout << "[!] foundzzzzzzzzzzzzzz!";
					WorldInfo* world = getPlyersWorld(peer);
					ENetPeer* currentPeer;
					for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
					{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
							continue;
						if (isHere(peer, currentPeer)) {
							BlockVisual data;
							data.packetType = 0x5;
							data.characterState = 8;
							data.punchX = x;
							data.punchY = y;
							data.charStat = 13; // 13y
							data.blockid = 2946; // 2946 3794 = display shelf
												 //data.netID = ((PlayerInfo*)(peer->data))->netID;
							data.backgroundid = 6864;
							data.visual = 0x00010000; //0x00210000

							std::ifstream ifs("display/" + worldInfo->name + "X" + std::to_string(squaresign) + ".txt");
							std::string content((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
							int id = atoi(content.c_str());

							world->items[x + (y * world->width)].displayblock = id;

							int n = id;
							string hex = "";
							{
								std::stringstream ss;
								ss << std::hex << n; // int decimal_value
								std::string res(ss.str());

								hex = res + "17";
							}

							if (hex == "2017") {
								continue;
							}


							int xx;
							std::stringstream ss;
							ss << std::hex << hex;
							ss >> xx;
							data.displayblock = xx;


							SendPacketRaw(192, packBlockVisual(&data), 69, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);

						}
					}
				}
			}
		}
	}

	int otherpeople = 0;
	int count = 0;
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		count++;
		if (isHere(peer, currentPeer))
			otherpeople++;
	}
	int otherpeoples = otherpeople - 1;
	if (((PlayerInfo*)(peer->data))->haveGrowId) {
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 0) {
				((PlayerInfo*)(peer->data))->displayName = "`2" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
			else if (((PlayerInfo*)(peer->data))->legend == true) {
				((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->tankIDName + " of Legend";
			}
			else if (((PlayerInfo*)(peer->data))->level >= 125) {
				((PlayerInfo*)(peer->data))->displayName >= "`4Dr. " + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 0) {
				((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->tankIDName;
			}
			else if (((PlayerInfo*)(peer->data))->legend == true) {
				((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->tankIDName + " of Legend";
			}
			else if (((PlayerInfo*)(peer->data))->level >= 125) {
				((PlayerInfo*)(peer->data))->displayName >= "`4Dr. " + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	else
	{
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 0) {
				((PlayerInfo*)(peer->data))->displayName = "`2" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
			else if (((PlayerInfo*)(peer->data))->legend == true) {
				((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->tankIDName + " of Legend";
			}
			else if (((PlayerInfo*)(peer->data))->level >= 125) {
				((PlayerInfo*)(peer->data))->displayName >= "`4Dr. " + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 0) {
				((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->tankIDName;
			}
			else if (((PlayerInfo*)(peer->data))->legend == true) {
				((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->tankIDName + " of Legend";
			}
			else if (((PlayerInfo*)(peer->data))->level >= 125) {
				((PlayerInfo*)(peer->data))->displayName >= "`4Dr. " + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	if (((PlayerInfo*)(peer->data))->haveGrowId) {
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 111) {
				((PlayerInfo*)(peer->data))->displayName = "`$@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 111) {
				((PlayerInfo*)(peer->data))->displayName = "`$@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	else
	{
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 111) {
				((PlayerInfo*)(peer->data))->displayName = "`$@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 111) {
				((PlayerInfo*)(peer->data))->displayName = "`$@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	if (((PlayerInfo*)(peer->data))->haveGrowId) {
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 444) {
				((PlayerInfo*)(peer->data))->displayName = "`#@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 444) {
				((PlayerInfo*)(peer->data))->displayName = "`#@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	else
	{
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 444) {
				((PlayerInfo*)(peer->data))->displayName = "`#@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 444) {
				((PlayerInfo*)(peer->data))->displayName = "`#@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	if (((PlayerInfo*)(peer->data))->haveGrowId) {
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 666) {
				((PlayerInfo*)(peer->data))->displayName = "`w[`4Administrator`w] " + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 666) {
				((PlayerInfo*)(peer->data))->displayName = "`w[`4Administrator`w] " + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	else
	{
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 666) {
				((PlayerInfo*)(peer->data))->displayName = "`w[`4Administrator`w] " + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 666) {
				((PlayerInfo*)(peer->data))->displayName = "`w[`4Administrator`w] " + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	if (((PlayerInfo*)(peer->data))->haveGrowId) {
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 777) {
				((PlayerInfo*)(peer->data))->displayName = "`4@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 777) {
				((PlayerInfo*)(peer->data))->displayName = "`4@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	else
	{
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 777) {
				((PlayerInfo*)(peer->data))->displayName = "`4@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 777) {
				((PlayerInfo*)(peer->data))->displayName = "`4@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	if (((PlayerInfo*)(peer->data))->haveGrowId) {
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 999) {
				((PlayerInfo*)(peer->data))->displayName = "`6@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 999) {
				((PlayerInfo*)(peer->data))->displayName = "`6@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	else
	{
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 999) {
				((PlayerInfo*)(peer->data))->displayName = "`6@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 999) {
				((PlayerInfo*)(peer->data))->displayName = "`6@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	if (((PlayerInfo*)(peer->data))->haveGrowId) {
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 1337) {
				((PlayerInfo*)(peer->data))->displayName = "`c@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 1337) {
				((PlayerInfo*)(peer->data))->displayName = "`c@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	else
	{
		if (((PlayerInfo*)(peer->data))->rawName == worldInfo->owner)
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 1337) {
				((PlayerInfo*)(peer->data))->displayName = "`c@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
		else
		{
			if (((PlayerInfo*)(peer->data))->adminLevel == 1337) {
				((PlayerInfo*)(peer->data))->displayName = "`c@" + ((PlayerInfo*)(peer->data))->tankIDName;
			}
		}
	}
	string act = ((PlayerInfo*)(peer->data))->currentWorld;
	sendState(peer);
	if (worldInfo->weather == 29) {
		updateStuffWeather(peer, 0, 0, worldInfo->rainitem, 0, worldInfo->stuffgrav, false, false);
	}
	else {
		GamePacket p7 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), worldInfo->weather));
		ENetPacket* packet7 = enet_packet_create(p7.data,
			p7.len,
			ENET_PACKET_FLAG_RELIABLE);

		enet_peer_send(peer, 0, packet7);
		delete p7.data;
	}
	string nameworld = worldInfo->name;
	string ownerworld = worldInfo->owner;
	string accessname = "";
	for (std::vector<string>::const_iterator i = worldInfo->acclist.begin(); i != worldInfo->acclist.end(); ++i) {
		accessname = *i;
	}
	if (worldInfo->owner == ((PlayerInfo*)(peer->data))->rawName)
	{

		GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5[`0" + nameworld + " `$World Locked `oby " + ownerworld + " ``(`2ACCESS GRANTED``)`5]"));
		ENetPacket* packet3 = enet_packet_create(p3.data,
			p3.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet3);
		delete p3.data;





	}
	else if (((PlayerInfo*)(peer->data))->rawName == accessname)
	{

		GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5[`0" + nameworld + " `$World Locked `oby " + ownerworld + " ``(`2ACCESS GRANTED``)`5]"));
		ENetPacket* packet3 = enet_packet_create(p3.data,
			p3.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet3);
		delete p3.data;





	}
	else if (((PlayerInfo*)(peer->data))->adminLevel == 1337)
	{
		if (ownerworld != "") {
			GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5[`0" + nameworld + " `$World Locked `oby " + ownerworld + " ``(`2ACCESS GRANTED``)`5]"));
			ENetPacket* packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet3);
			delete p3.data;

		}





	}

	else
	{

		if (ownerworld != "") {
			GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5[`0" + nameworld + " `$World Locked `oby " + ownerworld + "`5]"));
			ENetPacket* packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet3);
			delete p3.data;
		}
	}
	delete data;
}
void joinWorld(ENetPeer* peer, string act, int x2, int y2)
{
	try {
		WorldInfo info = worldDB.get(act);
		sendWorld(peer, &info);


		int x = 3040;
		int y = 736;

		for (int j = 0; j < info.width * info.height; j++)
		{
			if (info.items[j].foreground == 6) {
				x = (j % info.width) * 32;
				y = (j / info.width) * 32;
			}
		}
		if (x2 != 0 && y2 != 0)
		{
			x = x2;
			y = y2;
		}
		int id = 244;
		int uid = ((PlayerInfo*)(peer->data))->userID;
		if (((PlayerInfo*)(peer->data))->adminLevel > 1336)
		{

			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(uid) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "|" + std::to_string(id) + "\ninvis|0\nmstate|0\nsmstate|1\ntype|local\n"));
			//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
		}
		else
		{

			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(uid) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "|" + std::to_string(id) + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
			//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(cId) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));
			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);

			delete p.data;
		}

		/* Weather change
		{
			GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), info.weather));
			ENetPacket * packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
		}
		*/

		((PlayerInfo*)(peer->data))->netID = cId;
		onPeerConnect(peer);
		cId++;
		sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);


		WorldInfo* world = getPlyersWorld(peer);
		string nameworld = world->name;
		string ownerworld = world->owner;
		int count = 0;
		ENetPeer* currentPeer;
		string name = "";
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			count++;
		}


		{
			ENetPeer* currentPeer;

			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer))
				{


					GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet2);
					delete p2.data;
					continue;
				}
			}
		}


		int otherpeople = 0;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer))
				otherpeople++;
		}
		int otherpeoples = otherpeople - 1;

		GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oWorld `0" + nameworld + " `oentered. There are `0" + std::to_string(otherpeoples) + " `oother people here`7, `0" + std::to_string(count) + " `oonline."));
		ENetPacket* packet2 = enet_packet_create(p2.data,
			p2.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet2);
		delete p2.data;

		GamePacket p22 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5<`w" + ((PlayerInfo*)(peer->data))->displayName + "`` `5entered, `w" + std::to_string(otherpeoples) + "`` others here>``"));

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				{

					ENetPacket* packet2 = enet_packet_create(p22.data,
						p22.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);
					sendSound(currentPeer, "door_open.wav");
				}
			}
		}
	}
	catch (int e) {
		if (e == 1) {
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have exited the world."));
			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			//enet_host_flush(server);
		}
		else if (e == 2) {
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have entered bad characters in the world name!"));
			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			//enet_host_flush(server);
		}
		else if (e == 3) {
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Exit from what? Click back if you're done playing."));
			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			//enet_host_flush(server);
		}
		else {
			((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] I know this menu is magical and all, but it has its limitations! You can't visit this world!"));
			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			//enet_host_flush(server);
		}
	}
}
void autosave()
{
	bool exist = std::experimental::filesystem::exists("save.txt");
	if (!exist)
	{
		ofstream save("save.txt");
		save << 0;
		save.close();
	}
	std::ifstream ok("save.txt");
	std::string limits((std::istreambuf_iterator<char>(ok)),
		(std::istreambuf_iterator<char>()));
	int a = atoi(limits.c_str());
	if (a == 0)
	{
		ofstream ok;
		ok.open("save.txt");
		ok << 50;
		ok.close();
		worldDB.saveAll();
		cout << "[!]Auto Saving Worlds" << endl;
	}
	else
	{
		int aa = a - 1;
		ofstream ss;
		ss.open("save.txt");
		ss << aa;
		ss.close();
		if (aa == 0)
		{
			ofstream ok;
			ok.open("save.txt");
			ok << 50;
			ok.close();
			worldDB.saveAll();
			cout << "[!]Auto Saving Worlds" << endl;
		}
	}
}
void doublejump(ENetPeer* peer)
{
	if (((PlayerInfo*)(peer->data))->cloth_back != 0) {
		((PlayerInfo*)(peer->data))->canDoubleJump = true;
	}
}
void updateInvis(ENetPeer* peer)
{
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			autosave();
			GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), ((PlayerInfo*)(peer->data))->isInvisible));

			memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
			ENetPacket* packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2);
			delete p2.data;

			GamePacket p3 = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), ((PlayerInfo*)(currentPeer->data))->isInvisible));

			memcpy(p3.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
			ENetPacket* packet3 = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet3);
			delete p3.data;


			GamePacket p2ww = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(peer->data))->country + "|showGuild"));
			memcpy(p2ww.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
			ENetPacket* packet2ww = enet_packet_create(p2ww.data,
				p2ww.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2ww);
			delete p2ww.data;
			GamePacket p2wwee = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(currentPeer->data))->country + "|showGuild"));
			memcpy(p2wwee.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
			ENetPacket* packet2wwee = enet_packet_create(p2wwee.data,
				p2wwee.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet2wwee);
			delete p2wwee.data;

			int flag1 = (65536 * ((PlayerInfo*)(peer->data))->guildBg) + ((PlayerInfo*)(peer->data))->guildFg;
			GamePacket p2gg = packetEnd(appendIntx(appendIntx(appendIntx(appendIntx(appendString(createPacket(), "OnGuildDataChanged"), 41179607), 41179607), flag1), 0));

			memcpy(p2gg.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
			ENetPacket* packet2gg = enet_packet_create(p2gg.data,
				p2gg.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2gg);
			delete p2gg.data;
			int flag2 = (65536 * ((PlayerInfo*)(currentPeer->data))->guildBg) + ((PlayerInfo*)(currentPeer->data))->guildFg;
			GamePacket p2xd = packetEnd(appendIntx(appendIntx(appendIntx(appendIntx(appendString(createPacket(), "OnGuildDataChanged"), 41179607), 41179607), flag2), 0));

			memcpy(p2xd.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
			ENetPacket* packet2xd = enet_packet_create(p2xd.data,
				p2xd.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet2xd);
			delete p2xd.data;
		}
		doublejump(peer);
	}
}

void sendPlayerLeave(ENetPeer* peer, PlayerInfo* player)
{
	//((PlayerInfo*)(peer->data))->cpX = 3040;
	//((PlayerInfo*)(peer->data))->cpY = 736;
	((PlayerInfo*)(peer->data))->checky = 0;
	((PlayerInfo*)(peer->data))->checkx = 0;
	((PlayerInfo*)(peer->data))->ischeck = false;
	ENetPeer* currentPeer;
	string online = "";
	int total = 0;

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (getAdminLevel(((PlayerInfo*)(currentPeer->data))->rawName, ((PlayerInfo*)(currentPeer->data))->tankIDPass) >= 0) {
			total++;
		}
	}
	GamePacket p5 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oWhere would you like to go? (`w" + to_string(total) + " `oonline)"));
	ENetPacket* packet5 = enet_packet_create(p5.data,
		p5.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet5);
	delete p5.data;
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnRemove"), "netID|" + std::to_string(player->netID) + "\n")); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
	GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5<`w" + ((PlayerInfo*)(peer->data))->displayName + "`` `5left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + "`` `5others here>```w"));
	string name = ((PlayerInfo*)(peer->data))->displayName;
	string text = "action|play_sfx\nfile|audio/door_shut.wav\ndelayMS|0\n";
	BYTE* data = new BYTE[5 + text.length()];
	BYTE zero = 0;
	int type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;

		if (isHere(peer, currentPeer)) {
			{

				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);

				{

					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet);
					ENetPacket* packet3 = enet_packet_create(data,
						5 + text.length(),
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet3);

				}
				if (((PlayerInfo*)(peer->data))->isInvisible == false)
				{
					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet2);


					GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`5<`w" + ((PlayerInfo*)(peer->data))->displayName + "`` `5left, `w" + std::to_string(getPlayersCountInWorld(player->currentWorld) - 1) + "`` `5others here>```w"));
					ENetPacket* packet4 = enet_packet_create(p4.data,
						p4.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet4);
					delete p4.data;
				}
			}
			{

			}
		}
	}
	delete p.data;
	delete p2.data;
}
void sendPlayerToPlayer(ENetPeer* peer, ENetPeer* otherpeer)
{
	{
		sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
	}
	WorldInfo info = worldDB.get(((PlayerInfo*)(otherpeer->data))->currentWorld);
	sendWorld(peer, &info);


	int x = ((PlayerInfo*)(otherpeer->data))->x;
	int y = ((PlayerInfo*)(otherpeer->data))->y;


	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(((PlayerInfo*)(peer->data))->userID) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));


	ENetPacket * packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);


	delete p.data;
	((PlayerInfo*)(peer->data))->netID = cId;
	onPeerConnect(peer);
	cId++;


	sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
}

string timegt() {
#pragma warning(disable: 4996)
	time_t currentTime;
	struct tm *localTime;
	char buffer[80];

	time(&currentTime); // Get the current time
	localTime = localtime(&currentTime); // Convert the current time to the local time

	int yer = localTime->tm_year + 1900;
	int Mon = localTime->tm_mon + 1;
	int Day = localTime->tm_mday;
	int Hour = localTime->tm_hour;
	int Min = localTime->tm_min;
	int Sec = localTime->tm_sec;

	strftime(buffer, sizeof(buffer), "%d/%m/%Y", localTime);
	std::string str(buffer);

	return str;
}
bool hasPassed1(string dw) {
	string ee = timegt();
	bool result = false;
	vector<string> ex1 = explode("/", ee);
	int d1 = stoi(ex1[0]);
	int m1 = stoi(ex1[1]);
	int y1 = stoi(ex1[2]);

	vector<string> ex = explode("/", dw);
	int d = stoi(ex[0]);
	int m = stoi(ex[1]);
	int y = stoi(ex[2]);

	if (y1 >= y) {
		if (m1 >= m) {
			if (d1 > d) {
				result = true;
			}
		}
	}
	return result;
}
string getExpire3(string name) {
	string result = "";
	std::ifstream ads("atm.txt");
	for (std::string line; getline(ads, line);)
	{
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);
		std::transform(line.begin(), line.end(), line.begin(), ::tolower);
		vector<string> ex = explode("|", line);
		if (ex[0] == name) {
			if (ex[1] == "perma") {
				result = "69/420/1337";
			}
			else {
				result = ex[1];
			}
		}
	}
	return result;
}
int checkatm(string name) {
	std::ifstream ads("atm.txt");
	int result = 0;
	for (std::string line; getline(ads, line);)
	{
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);
		std::transform(line.begin(), line.end(), line.begin(), ::tolower);
		vector<string> ex = explode("|", line);
		if (ex[0] == name) {
			if (ex[1] == "perma") {
				return 2;
			}
			else {
				if (hasPassed1(ex[1]))
					result = 1;
				else
					result = 2;
			}

		}
	}
	printf(to_string(result).c_str());
	return result;
}
bool hasPassed2(string dw) {
	string ee = timegt();
	bool result = false;
	vector<string> ex1 = explode("/", ee);
	int d1 = stoi(ex1[0]);
	int m1 = stoi(ex1[1]);
	int y1 = stoi(ex1[2]);

	vector<string> ex = explode("/", dw);
	int d = stoi(ex[0]);
	int m = stoi(ex[1]);
	int y = stoi(ex[2]);

	if (y1 >= y) {
		if (m1 >= m) {
			if (d1 > d) {
				result = true;
			}
		}
	}
	return result;
}
string getExpire4(string name) {
	string result = "";
	std::ifstream ads("cow.txt");
	for (std::string line; getline(ads, line);)
	{
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);
		std::transform(line.begin(), line.end(), line.begin(), ::tolower);
		vector<string> ex = explode("|", line);
		if (ex[0] == name) {
			if (ex[1] == "perma") {
				result = "69/420/1337";
			}
			else {
				result = ex[1];
			}
		}
	}
	return result;
}
int checkcow(string name) {
	std::ifstream ads("cow.txt");
	int result = 0;
	for (std::string line; getline(ads, line);)
	{
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);
		std::transform(line.begin(), line.end(), line.begin(), ::tolower);
		vector<string> ex = explode("|", line);
		if (ex[0] == name) {
			if (ex[1] == "perma") {
				return 2;
			}
			else {
				if (hasPassed2(ex[1]))
					result = 1;
				else
					result = 2;
			}

		}
	}
	printf(to_string(result).c_str());
	return result;
}
bool hasPassed(string dw) {
	string ee = timegt();
	bool result = false;
	vector<string> ex1 = explode("/", ee);
	int d1 = stoi(ex1[0]);
	int m1 = stoi(ex1[1]);
	int y1 = stoi(ex1[2]);

	vector<string> ex = explode("/", dw);
	int d = stoi(ex[0]);
	int m = stoi(ex[1]);
	int y = stoi(ex[2]);

	if (y1 >= y) {
		if (m1 >= m) {
			if (d1 > d) {
				result = true;
			}
		}
	}
	return result;
}
string getExpire2(string name) {
	string result = "";
	std::ifstream ads("event.txt");
	for (std::string line; getline(ads, line);)
	{
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);
		std::transform(line.begin(), line.end(), line.begin(), ::tolower);
		vector<string> ex = explode("|", line);
		if (ex[0] == name) {
			if (ex[1] == "perma") {
				result = "69/420/1337";
			}
			else {
				result = ex[1];
			}
		}
	}
	return result;
}
int checkmute(string name) {
	std::ifstream ads("event.txt");
	int result = 0;
	for (std::string line; getline(ads, line);)
	{
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);
		std::transform(line.begin(), line.end(), line.begin(), ::tolower);
		vector<string> ex = explode("|", line);
		if (ex[0] == name) {
			if (ex[1] == "perma") {
				return 2;
			}
			else {
				if (hasPassed(ex[1]))
					result = 1;
				else
					result = 2;
			}

		}
	}
	printf(to_string(result).c_str());
	return result;
}
void sendTileUpdate(int x, int y, int tile, int causedBy, ENetPeer* peer)
{
	bool isLock = false;
	bool ismonitor = false;
	bool ismag = false;
	PlayerInfo *pinfo = ((PlayerInfo*)(peer->data));
	PlayerMoving data;
	//data.packetType = 0x14;
	data.packetType = 0x3;


	//data.characterState = 0x924; // animation
	data.characterState = 0x0; // animation
	data.x = x;
	data.y = y;
	data.punchX = x;
	data.punchY = y;
	data.XSpeed = 0;
	data.YSpeed = 0;
	data.netID = causedBy;
	data.plantingTree = tile;

	WorldInfo *world = getPlyersWorld(peer);
	if (world == NULL) return;
	if (x<0 || y<0 || x>world->width || y>world->height) return;
	sendNothingHappened(peer, x, y);
	if (world->items[x + (y * world->width)].foreground == 2946 && tile != 18 && tile > 0) {
		if (((PlayerInfo*)(peer->data))->rawName == world->owner) {
			((PlayerInfo*)(peer->data))->blockx = x;
			((PlayerInfo*)(peer->data))->blocky = y;
			ENetPeer* currentPeer;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer)) {
					BlockVisual data;
					data.packetType = 0x5;
					data.characterState = 8;
					data.punchX = x;
					data.punchY = y;
					data.charStat = 13; // 13
					data.blockid = 2946; // 2946 3794 = display shelf
					//data.netID = ((PlayerInfo*)(peer->data))->netID;
					data.backgroundid = 6864;
					data.visual = 0x00010000; //0x00210000
					world->items[x + (y * world->width)].displayblock = tile;

					int n = tile;

					string hex = "";
					{
						std::stringstream ss;
						ss << std::hex << n; // int decimal_value
						std::string res(ss.str());

						hex = res + "17";
					}
					int squaresign = ((PlayerInfo*)(peer->data))->blockx + (((PlayerInfo*)(peer->data))->blocky * 100);
					string world = ((PlayerInfo*)(peer->data))->currentWorld;
					std::ofstream outfile("display/" + world + "X" + std::to_string(squaresign) + ".txt");
					outfile << n;
					outfile.close();


					int xx;
					std::stringstream ss;
					ss << std::hex << hex;
					ss >> xx;
					data.displayblock = xx;

					SendPacketRaw(192, packBlockVisual(&data), 69, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
				}
			}
			return;
		}
	}
	if (((PlayerInfo*)(peer->data))->adminLevel < 334) {
		if (world->items[x + (y*world->width)].foreground == 6 || world->items[x + (y*world->width)].foreground == 8 || world->items[x + (y * world->width)].foreground == 7372 || world->items[x + (y*world->width)].foreground == 3760) {

			GamePacket p2 = packetEnd(appendIntx(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`wIt's too strong to break."), 0), 1));
			ENetPacket* packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet2);
			delete p2.data;
			return;
		}
		if (tile == 6 || tile == 8 || tile == 3760 || tile == 1000 || tile == 7372)
		{
			GamePacket p2 = packetEnd(appendIntx(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`wIt's too heavy to place."), 0), 1));
			ENetPacket* packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet2);
			delete p2.data;
			return;
		}

	}
	if (tile == 1241) {
		updateVendMsg(peer, world->items[x + (y*world->width)].foreground, x, y, "`w" + world->owner + "\n`Status : `2ONLINE");
	}
	if (tile == 868) {
		sendConsoleMsg(peer, "You're getting stronger! `$(Milk, mod added)");
		((PlayerInfo*)(peer->data))->milk = true;
		return;

	}
	if (tile == 2480) {
		GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|`wMegaphone|left|2480|\nadd_spacer|small|\nadd_label_with_icon|small|`oThis will broadcast to all players in the server!|left|486|\nadd_spacer|small|\nadd_text_input|sbtext|||50|\nend_dialog|sendsb|Cancel|Broadcast!|\n"));
		ENetPacket* packet2 = enet_packet_create(p2.data,
			p2.len,
			ENET_PACKET_FLAG_RELIABLE);

		enet_peer_send(peer, 0, packet2);
		delete p2.data;
		return;
	}
	if (tile == 822) {
		if (world->owner == "" || ((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner) || ((PlayerInfo*)(peer->data))->adminLevel > 1336) {
			if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK)
			{

				return;
			}
			world->items[x + (y*world->width)].water = !world->items[x + (y*world->width)].water;
			UpdateVisualsForBlock(peer, true, x, y, world);
			//cout << "[!] xd" << endl;

			return;
		}
	}
	if (tile == 3062)
	{
		if (world->owner == "" || ((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner) || ((PlayerInfo*)(peer->data))->adminLevel > 1336) {
			if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK)
			{

				return;
			}
			world->items[x + (y*world->width)].fire = !world->items[x + (y*world->width)].fire;
			UpdateVisualsForBlock(peer, true, x, y, world);
			return;
		}
	}
	if (tile == 18) {
		if (world->owner == "" || ((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner) || ((PlayerInfo*)(peer->data))->adminLevel > 1336) {
			if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::TOGGLE_FOREGROUND)
			{



				if (world->items[x + (y*world->width)].active == true) {
					world->items[x + (y*world->width)].active = false;
					UpdateBlockState(peer, x, y, true, world);
				}
				else {
					world->items[x + (y*world->width)].active = true;
					UpdateBlockState(peer, x, y, true, world);
				}

			}
		}
	}

	if (tile == 1866)
	{
		if (world->owner == "" || ((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner)  || ((PlayerInfo*)(peer->data))->adminLevel > 1336) {
			if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK)
			{
				cout << "[!] Tried paint wl!";
				return;
			}
			world->items[x + (y*world->width)].glue = !world->items[x + (y*world->width)].glue;
			UpdateVisualsForBlock(peer, true, x, y, world);
			return;
		}
	}
	if (pinfo->cloth_hand == 3494) // paint buckets
	{
		if (world->owner == "" || ((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner)  || ((PlayerInfo*)(peer->data))->adminLevel > 1336) {
			//if (world->items[x + (y * world->width)].foreground == 242 && world->items[x + (y * world->width)].foreground == 1796 && world->items[x + (y * world->width)].foreground == 2408 && world->items[x + (y * world->width)].foreground == 7188 && world->items[x + (y * world->width)].foreground == 4802) return;

			switch (tile)
			{
			case 3478:
				if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK)
				{

					return;
				}
				world->items[x + (y*world->width)].red = true;
				world->items[x + (y*world->width)].green = false;
				world->items[x + (y*world->width)].blue = false;
				UpdateVisualsForBlock(peer, true, x, y, world);
				return;
			case 3480:
				if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK)
				{

					return;
				}
				world->items[x + (y*world->width)].red = true;
				world->items[x + (y*world->width)].green = true;
				world->items[x + (y*world->width)].blue = false;
				UpdateVisualsForBlock(peer, true, x, y, world);
				return;
			case 3482:
				if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK)
				{
					return;
				}
				world->items[x + (y*world->width)].red = false;
				world->items[x + (y*world->width)].green = true;
				world->items[x + (y*world->width)].blue = false;
				UpdateVisualsForBlock(peer, true, x, y, world);
				return;
			case 3484:
				if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK || world->items[x + (y*world->width)].foreground == 2946)
				{

					return;
				}
				world->items[x + (y*world->width)].red = false;
				world->items[x + (y*world->width)].green = true;
				world->items[x + (y*world->width)].blue = true;
				UpdateVisualsForBlock(peer, true, x, y, world);
				return;
			case 3486:
				if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK || world->items[x + (y*world->width)].foreground == 2946)
				{

					return;
				}
				world->items[x + (y*world->width)].red = false;
				world->items[x + (y*world->width)].green = false;
				world->items[x + (y*world->width)].blue = true;
				UpdateVisualsForBlock(peer, true, x, y, world);
				return;
			case 3488:
				if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK || world->items[x + (y*world->width)].foreground == 2946)
				{

					return;
				}
				world->items[x + (y*world->width)].red = true;
				world->items[x + (y*world->width)].green = false;
				world->items[x + (y*world->width)].blue = true;
				UpdateVisualsForBlock(peer, true, x, y, world);
				return;
			case 3490:
				if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK || world->items[x + (y*world->width)].foreground == 2946)
				{

					return;
				}
				world->items[x + (y*world->width)].red = true;
				world->items[x + (y*world->width)].green = true;
				world->items[x + (y*world->width)].blue = true;
				UpdateVisualsForBlock(peer, true, x, y, world);
				return;
			case 3492:
				if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::LOCK || world->items[x + (y*world->width)].foreground == 2946)
				{

					return;
				}
				world->items[x + (y*world->width)].red = false;
				world->items[x + (y*world->width)].green = false;
				world->items[x + (y*world->width)].blue = false;
				UpdateVisualsForBlock(peer, true, x, y, world);
				return;
			default: break;
			}
		}
	}

	if (tile == 18)
	{
		if (world->items[x + (y * world->width)].foreground == 758)
		{
			sendRoulete(peer);
		}
	}
	if (world->name == "ADMIN" && !getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
	{
		return;
	}
	if (tile == 18) {
		if (world->items[x + (y * world->width)].foreground == 758) {
			sendRoulete(peer);
	    }
	}
	if (world->items[x + (y*world->width)].foreground == 1008)
	{
		if (tile == 18) {
			if (checkatm(((PlayerInfo*)(peer->data))->rawName) == 2) {
				GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oSorry You cant take your atm now! `5(" + getExpire3(((PlayerInfo*)(peer->data))->rawName) + ")"));
				ENetPacket * packet = enet_packet_create(p3.data,
					p3.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);
				delete p3.data;
			}
			else {
				int netid = -1;
				std::vector<int> lists{ 50, 100, 5, 5, 10, 1, 1, 1 };
				int indexs = rand() % lists.size(); // pick a random index
				int values = lists[indexs];
				DropItem(peer, -1, x * 32, y * 32, 112, values, 0);
#pragma warning(disable: 4996)
				time_t currentTime;
				struct tm *localTime;
				char buffer[80];

				time(&currentTime); // Get the current time
				localTime = localtime(&currentTime); // Convert the current time to the local time

				int yer = localTime->tm_year + 1900;
				int Mon = localTime->tm_mon + 1;
				int Day = localTime->tm_mday;
				int Hour = localTime->tm_hour;
				int Min = localTime->tm_min;
				int Sec = localTime->tm_sec;
				int IncHour = Hour + 1;
				if (IncHour >= 24) {
					int res = IncHour / 24;
					int newDay = IncHour % 24;
					Hour += res;
					if (Hour > 24) {
						Hour = 24;
					}
				}
				string usedban = ((PlayerInfo*)(peer->data))->rawName;

				std::fstream gay("atm.txt", std::ios::in | std::ios::out | std::ios::ate);
				gay << usedban + "|" << IncHour << "/" << Day << "/" << Mon << "/" << yer << endl;
				gay.close();
			}
		}
	}
	if (world->items[x + (y * world->width)].foreground == 1790)
	{


		if (tile == 18) {
			if (((PlayerInfo*)(peer->data))->haveGrowId == false) { // fix growid
				sendConsoleMsg(peer, "Create a growid first!");
			}
			else {
				string ownername = world->owner;

				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9The Legendary Wizard!`|left|1790|\nadd_label|small|`oGreetings, traveler! I am the Legendary Wizard. Should you wish to embark on a Legendary Quest, simply choose one below.``|left|4|\n\nadd_spacer|small|\nadd_button|legendname|`9Quest For Honor``|0|0|\nadd_button|legenddragon|`9Quest For Fire``|0|0|\nadd_button|legendbot|`9Quest Of Steel``|0|0|\nadd_button|legendwing|`9Quest Of The Heavens``|0|0|\nadd_button|legendkatana|`9Quest For The Blade``|0|0|\nadd_button|legendwhip|`9Quest For Candour``|0|0|\nadd_button|legendsky|`9Quest Of The Sky``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);

				//enet_host_flush(server);
				delete p.data;
			}

		}
	}
	if (world->items[x + (y * world->width)].foreground == 5638)
	{

		int noclap = 0;
		bool casin = world->magplant;
		if (casin == true) {
			noclap = 1;
		}
		else {
			noclap = 0;
		}
		if (tile == 32) {
			if (world->magplant == false) {
				if (((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner) || ((PlayerInfo*)(peer->data))->adminLevel > 1336) {
					string pricee = std::to_string(world->maggems);
					if (world->maggems == 0) {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wMagplant 5000`|left|5638|\nadd_label_with_icon|small|`2Gems``|left|112|\n\nadd_spacer|small|\nadd_label|small|`6The machine is currently empty!``|left|222|\nadd_label|small|`$Collecting mode : `4DISABLE|left|23|\nadd_spacer|small|\nadd_checkbox|enablemag|Enable magplant|" + std::to_string(noclap) + "|\nend_dialog|magplant|Close|Update"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wMagplant 5000`|left|5638|\nadd_label_with_icon|small|`2Gems``|left|112|\n\nadd_spacer|small|\nadd_label|small|`oThe machine contains `2" + pricee + " `ogems``|left|222|\nadd_button|takegems|`wCollect `2" + pricee + " `ogems!``|0|0|\nadd_label|small|`$Collecting mode : `4DISABLE|left|23|\nadd_spacer|small|\nadd_checkbox|enablemag|Enable magplant|" + std::to_string(noclap) + "|\nend_dialog|magplant|Close|Update"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
				}
			}
			else {
				if (((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner) || ((PlayerInfo*)(peer->data))->adminLevel > 1336) {
					string pricee = std::to_string(world->maggems);
					if (world->maggems == 0) {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wMagplant 5000`|left|5638|\nadd_label_with_icon|small|`2Gems``|left|112|\n\nadd_spacer|small|\nadd_label|small|`oThe machine is currently empty!``|left|222|\nadd_label|small|`$Collecting mode : `2ACTIVE|left|23|\nadd_spacer|small|\nadd_checkbox|enablemag|Enable magplant|" + std::to_string(noclap) + "|\nend_dialog|magplant|Close|Update"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wMagplant 5000`|left|5638|\nadd_label_with_icon|small|`2Gems``|left|112|\n\nadd_spacer|small|\nadd_label|small|`oThe machine contains `2" + pricee + " `ogems``|left|222|\nadd_button|takegems|`wCollect `2" + pricee + " `ogems!``|0|0|\nadd_label|small|`$Collecting mode : `2ACTIVE|left|23|\nadd_spacer|small|\nadd_checkbox|enablemag|Enable magplant|" + std::to_string(noclap) + "|\nend_dialog|magplant|Close|Update"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
				}
			}
		}
	}
	if (world->name == "TRASH") {
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 300)
			{
				int rubble = ((PlayerInfo*)(peer->data))->ban;
				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`7Trash-Man``|left|4794|\nadd_spacer|small|\nadd_label|small|`7You have: `2" + to_string(rubble) + " Rubble's!|left|\nadd_label_with_icon|small|`7Turning `21 Rubble `7give you `20-15 `7gems.|left|112|\nadd_spacer|small|\nadd_button|traderubble|`5Trade!|0|0|\nadd_button|cl0se|Close|0|0|"));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);

				//enet_host_flush(server);
				delete p.data;
			}
		}
	}
	if (world->name == "START") {
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 3682)
			{
				if (checkmute(((PlayerInfo*)(peer->data))->rawName) == 2) {
					GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Sorry You cant take your daily reward until `5(" + getExpire2(((PlayerInfo*)(peer->data))->rawName) + ")"));
					ENetPacket * packet = enet_packet_create(p3.data,
						p3.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p3.data;
				}
				else if (((PlayerInfo*)(peer->data))->haveGrowId == false) { // fix growid
					sendConsoleMsg(peer, "Create a growid first!");
				}
				else {
					string ownername = world->owner;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9Login`|left|3682|\nadd_label|small|`oGreetings, traveler! I am the Log in handler. Click the claim button to claim your reward!``|left|4|\n\nadd_spacer|small|\nadd_button|claim|`9Claim my daily prize!``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|Later||gazette||"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);

					//enet_host_flush(server);
					delete p.data;
				}

			}
		}
	}
	if (tile == 7484) {
		if (checkmute(((PlayerInfo*)(peer->data))->rawName) == 2) {
			GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Sorry You cant take your daily reward until `5(" + getExpire2(((PlayerInfo*)(peer->data))->rawName) + ")"));
			ENetPacket * packet = enet_packet_create(p3.data,
				p3.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p3.data;
		}
		else {
			GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|small|`oAre You Sure You Want To Open `1Winter chest`9?``|left|6200|\nadd_spacer|\nadd_button|openwinter|`2Open!|\nadd_quick_exit|"));
			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete p.data;
			return;
		}
	}
	if (world->items[x + (y * world->width)].foreground == 1900) {

		if (tile == 18) {
			if (((PlayerInfo*)(peer->data))->haveGrowId == false) { // fix growid
				sendConsoleMsg(peer, "Create a growid first!");
			}
			else {
				string ownername = world->owner;

				GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`9The Ringmaster!`|left|1900|\nadd_label|small|`oGreetings, traveler! I am the Ringmaster. Should you wish to embark on a Ring, simply choose one below.``|left|4|\n\nadd_spacer|small|\nadd_button|ringforce|`9Ring Of Force``|0|0|\nadd_button|ringwinds|`9Ring Of Winds``|0|0|\nadd_button|ringone|`9The One Ring``|0|0|\nadd_button|ringwisdom|`9Ring of Wisdom ``|0|0|\nadd_button|ringwater|`9Ring Of Water``|0|0|\nadd_button|ringsaving|`9Ring Of Savings``|0|0|\nadd_button|ringsmithing|`9Ring Of Smithing``|0|0|\nadd_button|ringshrinking|`9Ring Of Shrinking``|0|0|\nadd_button|ringnature|`9Ring of Nature``|0|0|\nadd_button|geminiring|`9Gemini Ring``|0|0|\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|noty|No Thanks||gazette||"));
				ENetPacket* packet = enet_packet_create(p.data,
					p.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet);

				//enet_host_flush(server);
				delete p.data;

				return;
			}
		}

	}
	string gay = world->items[x + (y * world->width)].text;
	int gay2 = world->items[x + (y * world->width)].foreground;
	if (getItemDef(world->items[x + (y*world->width)].foreground).blockType == BlockTypes::SIGN || world->items[x + (y * world->width)].foreground == 1420 || world->items[x + (y * world->width)].foreground == 6214)
	{
		if (world->owner != "") {
			if (((PlayerInfo*)(peer->data))->rawName == world->owner) {
				if (tile == 32) {
					((PlayerInfo*)(peer->data))->wrenchx = x;
					((PlayerInfo*)(peer->data))->wrenchy = y;
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEdit " + getItemDef(world->items[x + (y * world->width)].foreground).name + "``|left|" + to_string(gay2) + "|\n\nadd_textbox|`oWhat would you like to write on this sign?|\nadd_text_input|ch3||" + gay + "|100|\nembed_data|tilex|" + std::to_string(((PlayerInfo*)(peer->data))->wrenchx) + "\nembed_data|tiley|" + std::to_string(((PlayerInfo*)(peer->data))->wrenchy) + "\nend_dialog|sign_edit|Cancel|OK|"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
				}
			}
		}
	}
	if (getItemDef(world->items[x + (y * world->width)].foreground).blockType == BlockTypes::DOOR)
	{
		if (world->owner != "") {
			if (((PlayerInfo*)(peer->data))->rawName == world->owner) {
				if (tile == 32) {
					((PlayerInfo*)(peer->data))->wrenchsession = x + (y * world->width);
					WorldItem item = world->items[x + (y * world->width)];
					string a = item.destWorld + ":" + item.destId;
					if (a == ":") a = "";
					if (item.foreground == 762 || item.foreground == 4190)
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEdit Password Door``|left|" + to_string(item.foreground) + "|\n\nadd_text_input|dest|`oTarget World|" + a + "|100|\nadd_text_input|label|Display Label (optional)|" + item.label + "|100|\nadd_text_input|doorpw|Password|" + item.password + "|35|\nend_dialog|editpdoor|Cancel|OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					else {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEdit Door``|left|" + to_string(item.foreground) + "|\|\n\nadd_text_input|dest|`oTarget World|" + a + "|100|\nadd_text_input|label|Display Label (optional)|" + item.label + "|100|\nadd_text_input|doorid|ID (optional)|" + item.currId + "|35|\nend_dialog|editdoor|Cancel|OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
				}
			}
		}
	}
	if (world->name != "ADMIN") {
		if (world->owner != "") {

			string name = ((PlayerInfo*)(peer->data))->rawName;
			if (((PlayerInfo*)(peer->data))->rawName == world->owner || (find(world->acclist.begin(), world->acclist.end(), name) != world->acclist.end() || ((PlayerInfo*)(peer->data))->adminLevel == 1337)) {
				if (((PlayerInfo*)(peer->data))->rawName == "") return;
					// WE ARE GOOD TO GO

					if (world->items[x + (y * world->width)].foreground == 242 && (find(world->acclist.begin(), world->acclist.end(), name) != world->acclist.end()) || world->items[x + (y * world->width)].foreground == 1796 && (find(world->acclist.begin(), world->acclist.end(), name) != world->acclist.end()) || world->items[x + (y * world->width)].foreground == 4428 && (find(world->acclist.begin(), world->acclist.end(), name) != world->acclist.end()) || world->items[x + (y * world->width)].foreground == 2408 && (find(world->acclist.begin(), world->acclist.end(), name) != world->acclist.end()) || world->items[x + (y * world->width)].foreground == 7188 && (find(world->acclist.begin(), world->acclist.end(), name) != world->acclist.end()) || world->items[x + (y * world->width)].foreground == 5980 && (find(world->acclist.begin(), world->acclist.end(), name) != world->acclist.end()) || world->items[x + (y * world->width)].foreground == 2950 && (find(world->acclist.begin(), world->acclist.end(), name) != world->acclist.end()) || world->items[x + (y * world->width)].foreground == 5638 && (find(world->acclist.begin(), world->acclist.end(), name) != world->acclist.end()))
					{
						return;
					}

				if (tile == 32 && (find(world->acclist.begin(), world->acclist.end(), name) != world->acclist.end())) {
					return;
				}
				string offlinelist = "";
				string offname = "";
				int ischecked;
				int ischecked1;
				int ischecked2;
				for (std::vector<string>::const_iterator i = world->acclist.begin(); i != world->acclist.end(); ++i) {
					offname = *i;
					offlinelist += "\nadd_checkbox|isAccessed|" + offname + "|0|\n";

				}


				if (world->isPublic == true) {
					ischecked = 1;
				}
				else {
					ischecked = 0;
				}
				int noclap = 0;
				bool casin = world->isCasino;
				if (casin == true) { 
					noclap = 1;
				}
				else {
					noclap = 0;
				}
				if (tile == 32) {
					if (world->items[x + (y*world->width)].foreground == 242 || world->items[x + (y * world->width)].foreground == 5814 || world->items[x + (y * world->width)].foreground == 2408 || world->items[x + (y * world->width)].foreground == 1796 || world->items[x + (y * world->width)].foreground == 4428 || world->items[x + (y * world->width)].foreground == 7188) {

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wEdit " + GetItemDef(world->items[x + (y*world->width)].foreground).name + "``|left|" + to_string(world->items[x + (y*world->width)].foreground) + "|\nadd_textbox|`wAccess list:|left|\nadd_spacer|small|" + offlinelist + "add_spacer|small|\nadd_player_picker|netid|`wAdd|\nadd_spacer|small|\nadd_checkbox|isWorldPublic|Allow anyone to build|" + std::to_string(ischecked) + "|\nadd_checkbox|allowNoclip|Disable noclip|" + std::to_string(noclap) + "|\nend_dialog|wlmenu|Cancel|OK|"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
				}
			}
			else if (find(world->acclist.begin(), world->acclist.end(), ((PlayerInfo*)(peer->data))->rawName) != world->acclist.end())
			{
				if (world->items[x + (y*world->width)].foreground == 242 || world->items[x + (y * world->width)].foreground == 5814 || world->items[x + (y * world->width)].foreground == 2408 || world->items[x + (y * world->width)].foreground == 1796 || world->items[x + (y * world->width)].foreground == 4428 || world->items[x + (y * world->width)].foreground == 7188)
				{


					string ownername = world->owner;
					GamePacket p2 = packetEnd(appendIntx(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`0" + ownername + "'s `$World Lock`0. (`2Access Granted`w)"), 0), 1));


					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet2);
					delete p2.data;
					string text = "action|play_sfx\nfile|audio/punch_locked.wav\ndelayMS|0\n";
					BYTE* data = new BYTE[5 + text.length()];
					BYTE zero = 0;
					int type = 3;
					memcpy(data, &type, 4);
					memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
					memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

					ENetPacket* packetsou = enet_packet_create(data,
						5 + text.length(),
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packetsou);


					return;
				}

			}
			else if (world->isPublic)
			{
				if (world->items[x + (y*world->width)].foreground == 242 || world->items[x + (y * world->width)].foreground == 5814 || world->items[x + (y * world->width)].foreground == 2408 || world->items[x + (y * world->width)].foreground == 1796 || world->items[x + (y * world->width)].foreground == 4428 || world->items[x + (y * world->width)].foreground == 7188)
				{
					string ownername = world->owner;
					GamePacket p2 = packetEnd(appendIntx(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`0" + ownername + "'s `$World Lock`0. (`2Access Granted`w)"), 0), 1));


					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet2);
					delete p2.data;
					string text = "action|play_sfx\nfile|audio/punch_locked.wav\ndelayMS|0\n";
					BYTE* data = new BYTE[5 + text.length()];
					BYTE zero = 0;
					int type = 3;
					memcpy(data, &type, 4);
					memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
					memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

					ENetPacket* packetsou = enet_packet_create(data,
						5 + text.length(),
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packetsou);


					return;
				}

			}
			else {
				ItemDefinition pro;
				pro = getItemDef(world->items[x + (y * world->width)].foreground);
				if (world->items[x + (y*world->width)].foreground == 242 || world->items[x + (y * world->width)].foreground == 5814 || world->items[x + (y * world->width)].foreground == 2408 || world->items[x + (y * world->width)].foreground == 1796 || world->items[x + (y * world->width)].foreground == 4428 || world->items[x + (y * world->width)].foreground == 7188) {
					string ownername = world->owner;
					GamePacket p2 = packetEnd(appendIntx(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`0" + ownername + "'s `$World Lock`0. (`4No access`w)"), 0), 1));


					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet2);
					delete p2.data;
					string text = "action|play_sfx\nfile|audio/punch_locked.wav\ndelayMS|0\n";
					BYTE* data = new BYTE[5 + text.length()];
					BYTE zero = 0;
					int type = 3;
					memcpy(data, &type, 4);
					memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
					memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

					ENetPacket* packetsou = enet_packet_create(data,
						5 + text.length(),
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packetsou);


					return;
				}
				else
				{
					string text = "action|play_sfx\nfile|audio/punch_locked.wav\ndelayMS|0\n";
					BYTE* data = new BYTE[5 + text.length()];
					BYTE zero = 0;
					int type = 3;
					memcpy(data, &type, 4);
					memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
					memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

					ENetPacket* packetsou = enet_packet_create(data,
						5 + text.length(),
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(peer, 0, packetsou);


					return;
				}

			} /*lockeds*/
			if (tile == 242 || tile == 2408 || tile == 1796 || tile == 4428 || tile == 7188) {



				GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`0Only one `$World Lock`0 can be placed in a world!"), 0));


				ENetPacket * packet3 = enet_packet_create(p3.data,
					p3.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet3);
				delete p3.data;
				return;
			}
		}
	}
	if (tile == 18)
	{
		if (world->items[x + (y * world->width)].foreground == 1490)
		{
			world->weather = 10;
			ENetPeer* currentPeer;

			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer))
				{
					GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet2);
					delete p2.data;
					continue;
				}
			}
		}
	}
	// WE ARE GOOD TO GO
	if (tile == 18)
	{
		if (world->items[x + (y * world->width)].foreground == 934)
		{
			world->weather = 2;
			ENetPeer* currentPeer;

			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer))
				{
					GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
					ENetPacket* packet2 = enet_packet_create(p2.data,
						p2.len,
						ENET_PACKET_FLAG_RELIABLE);

					enet_peer_send(currentPeer, 0, packet2);
					delete p2.data;
					continue;
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 946)
			{
				world->weather = 3;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 1490)
			{
				world->weather = 10;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 932)
			{
				world->weather = 4;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 984)
			{
				world->weather = 5;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 1210)
			{
				world->weather = 8;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 1364)
			{
				world->weather = 11;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 1750)
			{
				world->weather = 15;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 2046)
			{
				world->weather = 17;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 2284)
			{
				world->weather = 18;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 2744)
			{
				world->weather = 19;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 3252)
			{
				world->weather = 20;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 3446)
			{
				world->weather = 21;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 3534)
			{
				world->weather = 22;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 3694)
			{
				world->weather = 25;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 3832)
			{
				world->weather = 29;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 1490)
			{
				world->weather = 10;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 4242)
			{
				world->weather = 30;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 4486)
			{
				world->weather = 31;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 4776)
			{
				world->weather = 32;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 4892)
			{
				world->weather = 33;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 5000)
			{
				world->weather = 34;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 5112)
			{
				world->weather = 35;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 5654)
			{
				world->weather = 36;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 5716)
			{
				world->weather = 37;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 5958)
			{
				world->weather = 38;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 6854)
			{
				world->weather = 42;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	{
		// WE ARE GOOD TO GO
		if (tile == 18)
		{
			if (world->items[x + (y * world->width)].foreground == 7644)
			{
				world->weather = 44;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), world->weather));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packet2);
						delete p2.data;
						continue;
					}
				}
			}
		}
	}
	if (tile == 1404) {
		//world->items[x + (y*world->width)].water = !world->items[x + (y*world->width)].water;
		//if (isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) {

		if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) {
			if (world->items[x + (y * world->width)].foreground != 0) {
				GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Here is no space for the main door!"));


				ENetPacket* packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet2);
				delete p2.data;

			}
			else if (world->items[x + (y * world->width) + 100].foreground != 0) {
				GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Here is no space for the main door!"));


				ENetPacket* packet2 = enet_packet_create(p2.data,
					p2.len,
					ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(peer, 0, packet2);
				delete p2.data;

			}
			else

			{
				//	showDoormover(peer);
				for (int i = 0; i < world->width * world->height; i++)
				{
					if (i >= 5400) {
						world->items[i].foreground = 8;
					}
					else if (world->items[i].foreground == 6) {

						world->items[i].foreground = 0;
						world->items[i + 100].foreground = 0;

					}

					else if (world->items[i].foreground != 6) {
						world->items[x + (y * world->width)].foreground = 6;
						world->items[x + (y * world->width) + 100].foreground = 8;
					}


				}

				WorldInfo* wrld = getPlyersWorld(peer);
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer))
					{
						string act = ((PlayerInfo*)(peer->data))->currentWorld;
						//WorldInfo info = worldDB.get(act);
						// sendWorld(currentPeer, &info);


						sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
						joinWorld(currentPeer, act, 0, 0);
						GamePacket p8 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You used door mover!"));
						ENetPacket* packet8 = enet_packet_create(p8.data,
							p8.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet8);

					}

				}
			}
			return;
		}
	}
	if (tile != 18)
	{
		if (world->items[x + (y * world->width)].foreground != 0) {
			return;
		}
	}
	if (tile == 32) {
		// TODO
		return;
	}
	if (tile == 1866)
	{
		world->items[x + (y * world->width)].glue = !world->items[x + (y * world->width)].glue;
		return;
	}
	ItemDefinition def;
	ItemDefinition proy;
	if (world->items[x + (y * world->width)].foreground == 0) {
		proy = getItemDef(world->items[x + (y * world->width)].background);
	}
	else {
		proy = getItemDef(world->items[x + (y * world->width)].foreground);
	}
	try {
		def = getItemDef(tile);
		if (def.clothType != ClothTypes::NONE) return;
	}
	catch (int e) {
		def.breakHits = 4;
		def.blockType = BlockTypes::UNKNOWN;
#ifdef TOTAL_LOG
		cout << "[!] Ugh, unsupported item " << tile << endl;
#endif
	}
	if (tile == 544 || tile == 546 || tile == 4520 || tile == 382 || tile == 3116 || tile == 4520 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
	if (tile == 5708 || tile == 5709 || tile == 5780 || tile == 5781 || tile == 5782 || tile == 5783 || tile == 5784 || tile == 5785 || tile == 5710 || tile == 5711 || tile == 5786 || tile == 5787 || tile == 5788 || tile == 5789 || tile == 5790 || tile == 5791 || tile == 6146 || tile == 6147 || tile == 6148 || tile == 6149 || tile == 6150 || tile == 6151 || tile == 6152 || tile == 6153 || tile == 5670 || tile == 5671 || tile == 5798 || tile == 5799 || tile == 5800 || tile == 5801 || tile == 5802 || tile == 5803 || tile == 5668 || tile == 5669 || tile == 5792 || tile == 5793 || tile == 5794 || tile == 5795 || tile == 5796 || tile == 5797 || tile == 544 || tile == 546 || tile == 4520 || tile == 382 || tile == 3116 || tile == 1792 || tile == 5666 || tile == 2994 || tile == 4368) return;
	if (tile == 1902 || tile == 1508 || tile == 428 || tile == 9496 || tile == 9499) return;
	if (tile == 18) {
		if (world->items[x + (y * world->width)].background == 6864 && world->items[x + (y * world->width)].foreground == 0) return;
		if (world->items[x + (y * world->width)].background == 0 && world->items[x + (y * world->width)].foreground == 0) return;
		//data.netID = -1;
		data.packetType = 0x8;
		data.plantingTree = 4;
		using namespace std::chrono;
		//if (world->items[x + (y*world->width)].foreground == 0) return;
		if ((duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() - world->items[x + (y * world->width)].breakTime >= 5000)
		{
			world->items[x + (y * world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
			world->items[x + (y * world->width)].breakLevel = 5; // TODO
		}
		else
			if (y < world->height && world->items[x + (y * world->width)].breakLevel + 5 >= def.breakHits * 5) { // TODO
				data.packetType = 0x3;// 0xC; // 0xF // World::HandlePacketTileChangeRequest
				data.netID = causedBy;
				data.plantingTree = 18;
				int brokentile = world->items[x + (y*world->width)].foreground;
				int hi = data.punchX * 32;
				int hi2 = data.punchY * 32;
				if (world->magplant == true) {
					GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 186), hi, hi2));
					ENetPacket* packetd = enet_packet_create(psp.data,
						psp.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packetd);
				}
				if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {
					if (brokentile == 242 || brokentile == 2408 || brokentile == 1796 || brokentile == 4428 || brokentile == 7188) {
						if (adminlevel(((PlayerInfo*)(peer->data))->rawName) < 111) {
							Player::OnNameChanged(peer, ((PlayerInfo*)(peer->data))->netID, "`0`0" + ((PlayerInfo*)(peer->data))->displayName);
						}
						SendTilePickup(peer, brokentile, ((PlayerInfo*)(peer->data))->netID, (float)x, (float)y, ((PlayerInfo*)(peer->data))->droppeditemcount, 1);
						bool success = true;
						SaveShopsItemMoreTimes(brokentile, ((PlayerInfo*)(peer->data))->droppeditemcount, peer, success);
						ENetPeer * currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer)) {
								Player::OnConsoleMessage(currentPeer, "`5[`w" + world->name + " `ohas had its `$World Lock `oremoved!`5]");
							}

							world->owner = "";
							world->isPublic = false;
							world->ownerID = 0;
							world->stuffID = 0;
							world->gravity = 0;
							world->acclist.clear();
						}
					}
				}
				//Player::SendTileAnimation(peer, x, y, causedBy, world->items[x + (y*world->width)].foreground);

				world->items[x + (y*world->width)].breakLevel = 0;
				if (brokentile != 0)
				{
					if (brokentile == 410 || brokentile == 1832 || brokentile == 1770) {
						int x1 = 0;
						int y1 = 0;
						for (int i = 0; i < world->width * world->height; i++)
						{
							if (world->items[i].foreground == 6) {
								x1 = (i % world->width) * 32;
								y1 = (i / world->width) * 32;
								//world->items[i].foreground = 8;
							}
						}
						ENetPeer * currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer)) {
								if (((PlayerInfo*)(currentPeer->data))->respawnX != 0 && ((PlayerInfo*)(currentPeer->data))->respawnY != 0) {
									if (((PlayerInfo*)(currentPeer->data))->respawnX / 32 == x && ((PlayerInfo*)(currentPeer->data))->respawnY / 32 == y) {
										((PlayerInfo*)(currentPeer->data))->respawnX = x1;
										((PlayerInfo*)(currentPeer->data))->respawnY = y1;
										Player::SetRespawnPos(currentPeer, x1 / 32, (world->width * (y1 / 32)), ((PlayerInfo*)(currentPeer->data))->netID);
									}
								}
							}
						}
						if (brokentile == 1008 || brokentile == 5638) {
							bool success = true;
							SaveShopsItemMoreTimes(brokentile, 1, peer, success);

						}
					}
					world->items[x + (y * world->width)].foreground = 0;
					if (world->magplant == true) {
						int multiplier = 60;
						if (((PlayerInfo*)(peer->data))->cloth_hand == 9490) {
							multiplier = 50;
						}
						else if (((PlayerInfo*)(peer->data))->cloth_feet == 8834) {
							multiplier = 40;
						}
						else if (((PlayerInfo*)(peer->data))->cloth_hand == 7912) {
							multiplier = 43;

						}
						else if (((PlayerInfo*)(peer->data))->cloth_hand == 6312) {
							multiplier = 28;
						}
						else if (((PlayerInfo*)(peer->data))->cloth_hand == 1836) {
							multiplier = 20;
						}
						else if (((PlayerInfo*)(peer->data))->level >= 11) {
							multiplier = 20;
						}
						else if (((PlayerInfo*)(peer->data))->level >= 50) {
							multiplier = 30;
						}
						else if (((PlayerInfo*)(peer->data))->level >= 100) {
							multiplier = 40;
						}
						else if (((PlayerInfo*)(peer->data))->level >= 150) {
							multiplier = 50;
						}
						else if (((PlayerInfo*)(peer->data))->level >= 200) {
							multiplier = 60;
						}
						int gemvalue = world->maggems += rand() % multiplier;
						world->maggems = gemvalue;

					}
					else {
						if (world->items[x + (y * world->width)].foreground == 2)
						{
							std::vector<int> list{ 112 };
							std::vector<int> lists{ 50, 5, 5, 10, 10, 1, 1, 1 };
							int indexs = rand() % lists.size(); // pick a random index
							int values = lists[indexs];
							DropItem(peer, -1, x * 32, y * 32, 112, values, 0);

						}
						else if (world->items[x + (y * world->width)].foreground == 866)
						{
							std::vector<int> lists{ 50, 5, 5, 10, 10, 1, 1, 1 };
							int indexs = rand() % lists.size(); // pick a random index
							int values = lists[indexs];
							DropItem(peer, -1, x * 32, y * 32, 112, values, 0);

						}
						else if (((PlayerInfo*)(peer->data))->cloth_feet == 8834) {
							std::vector<int> list{ 112 };
							std::vector<int> lists{ 1, 1, 1, 5, 5, 10, 10, 50, 100, 10, 10 };
							int indexs = rand() % lists.size(); // pick a random index
							int values = lists[indexs];
							DropItem(peer, -1, hi, hi2, 112, values, 0);
						}
						else if (((PlayerInfo*)(peer->data))->cloth_hand == 7912) {
							std::vector<int> list{ 112 };
							std::vector<int> lists{ 1, 1, 1, 5, 5, 10, 10, 50, 10, 10 };
							int indexs = rand() % lists.size(); // pick a random index
							int values = lists[indexs];
							DropItem(peer, -1, hi, hi2, 112, values, 0);
						}
						else if (((PlayerInfo*)(peer->data))->cloth_hand == 6312) {
							std::vector<int> list{ 112 };
							std::vector<int> lists{ 5, 10, 5, 5, 50, 100 };
							int indexs = rand() % lists.size(); // pick a random index
							int values = lists[indexs];
							DropItem(peer, -1, hi, hi2, 112, values, 0);
						}
						else if (((PlayerInfo*)(peer->data))->cloth_hand == 1836) {
							std::vector<int> list{ 112 };
							std::vector<int> lists{ 1, 1, 1, 5, 5, 10, 10, 50, 50 };
							int indexs = rand() % lists.size(); // pick a random index
							int values = lists[indexs];
							DropItem(peer, -1, hi, hi2, 112, values, 0);
						}
						else {
							std::vector<int> list{ 112 };
							std::vector<int> lists{ 50, 5, 5, 10, 10, 1, 1, 1 };
							int indexs = rand() % lists.size(); // pick a random index
							int values = lists[indexs];
							DropItem(peer, -1, x * 32, y * 32, 112, values, 0);
						}
					}
					((PlayerInfo*)(peer->data))->xp = ((PlayerInfo*)(peer->data))->xp + 1;
					int rubblechange = rand() % 100 + 1;
					if (rubblechange <= 5) {
						((PlayerInfo*)(peer->data))->ban = ((PlayerInfo*)(peer->data))->ban + 1;
						string name = ((PlayerInfo*)(peer->data))->displayName;

						GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`wYou found `2Rubble!"));
						ENetPacket* packet3 = enet_packet_create(p3.data,
							p3.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet3);
						int x = ((PlayerInfo*)(peer->data))->x;
						int y = ((PlayerInfo*)(peer->data))->y;
						GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 49), x, y));

						ENetPacket* packetd = enet_packet_create(psp.data,
							psp.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packetd);
						//GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->displayName + " was thrown a bucket of " + (((PlayerInfo*)(peer->data))->addgems)), 0));
					}
					if (((PlayerInfo*)(peer->data))->level == 1) {
						if (((PlayerInfo*)(peer->data))->xp >= 500) {
							((PlayerInfo*)(peer->data))->level = ((PlayerInfo*)(peer->data))->level = 5;
							((PlayerInfo*)(peer->data))->xp = 0;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {
									string name = ((PlayerInfo*)(peer->data))->tankIDName;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `w" + name + " `ois now level `w" + std::to_string(((PlayerInfo*)(peer->data))->level) + "`o!"));
									string text = "action|play_sfx\nfile|audio/levelup2.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);

									ENetPacket* packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									int effect = 46;
									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;
									GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

									ENetPacket* packetd = enet_packet_create(psp.data,
										psp.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd);

									//                `w(`2" + std::to_string(level) + "`w) "
									//((PlayerInfo*)(peer->data))->displayName = "`w(`2"+((PlayerInfo*)(peer->data))->level +"`w) " + ((PlayerInfo*)(peer->data))->tankIDName;
									delete psp.data;
									delete data;
									delete p.data;

									GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), name + " `ois now level `w" + std::to_string(((PlayerInfo*)(peer->data))->level) + "`o!"));
									ENetPacket* packet3 = enet_packet_create(p3.data,
										p3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);
									//GamePacket p3 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->displayName + " was thrown a bucket of " + (((PlayerInfo*)(peer->data))->addgems)), 0));

								}
							}
						}
					}
					else if (((PlayerInfo*)(peer->data))->level == 5) {

					}
					if (((PlayerInfo*)(peer->data))->haveGrowId) {
						savejson(peer);
					}
				}
				else {
					data.plantingTree = tile;
					world->items[x + (y * world->width)].background = 6864;
				}

			}
			else
				if (y < world->height)
				{
					world->items[x + (y * world->width)].breakTime = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					world->items[x + (y * world->width)].breakLevel += 4; // TODO
				}
	}
	else {
		for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
		{
			if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == tile)
			{
				if ((unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount > 1)
				{
					((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount--;
					SaveInventoryWhenBuildingBlock(peer);
				}
				else {
					((PlayerInfo*)(peer->data))->inventory.items.erase(((PlayerInfo*)(peer->data))->inventory.items.begin() + i);
					SaveInventoryWhenBuildingBlock(peer);
				}
			}
		}
		ItemDefinition yologay;
		if (def.blockType == BlockTypes::BACKGROUND)
		{
			world->items[x + (y * world->width)].background = tile;
		}
		else {
			ItemDefinition pro;
			pro = getItemDef(tile);
			if (tile == 5638) {
				ismag = true;

			}
			else if (tile == 242 || tile == 2408 || tile == 1796 || tile == 4428 || tile == 7188) {
				if (((PlayerInfo*)(peer->data))->rawName == world->owner) {
					return;
				}
				world->owner = ((PlayerInfo*)(peer->data))->rawName;
				world->ownerID = ((PlayerInfo*)(peer->data))->userID;
				isLock = true;
				world->isPublic = false;
				ENetPeer* currentPeer;

				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (isHere(peer, currentPeer)) {
						((PlayerInfo*)(peer->data))->worldsowned.push_back(world->name);
						std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


						if (ifff.fail()) {
							ifff.close();


						}
						if (ifff.is_open()) {
						}
						json j;
						ifff >> j; //load


						j["worldsowned"] = ((PlayerInfo*)(peer->data))->worldsowned; //edit




						std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
						if (!o.is_open()) {
							cout << GetLastError() << endl;
							_getch();
						}

						o << j << std::endl;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `3[`w" + world->name + " `ohas been World Locked by `2" + ((PlayerInfo*)(peer->data))->displayName + "`3]"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);
						delete p.data;
						GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "`2" + ((PlayerInfo*)(peer->data))->displayName));
						memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
						ENetPacket* packet3 = enet_packet_create(p3.data,
							p3.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet3);
						delete p3.data;
						((PlayerInfo*)(peer->data))->displayName = "`2" + ((PlayerInfo*)(peer->data))->tankIDName;
						string text = "action|play_sfx\nfile|audio/use_lock.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
						memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

						ENetPacket* packetsou = enet_packet_create(data,
							5 + text.length(),
							ENET_PACKET_FLAG_RELIABLE);

						enet_peer_send(currentPeer, 0, packetsou);
					}
				}
			}
			world->items[x + (y * world->width)].foreground = tile;
		}

		world->items[x + (y * world->width)].breakLevel = 0;
	}

	ENetPeer* currentPeer;

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		SendPacketRaw(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		//cout << "[!] Tile update at: " << data2->punchX << "x" << data2->punchY << endl;
	}
	if (isLock) {
		ENetPeer* currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				sendTileData(currentPeer, x, y, 0x10, tile, world->items[x + (y*world->width)].background, lockTileDatas(0x20, ((PlayerInfo*)(peer->data))->userID, 0, 0, false, 100));
			}
		}
	}
	if (ismag) {
		ENetPeer* currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				sendMag(peer, x, y, 112, 1, true, true);
			}
		}
	}
}
void sendChatMessage(ENetPeer* peer, int netID, string message)
{
	if (message.length() == 0) return;
	for (char c : message)

		if (c < 0x18 || std::all_of(message.begin(), message.end(), isspace)) {
			return;
		}
	ENetPeer* currentPeer;
	string name = "";
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (((PlayerInfo*)(currentPeer->data))->netID == netID)
			name = ((PlayerInfo*)(currentPeer->data))->displayName;

	}
	GamePacket p;
	GamePacket p2;
	if (((PlayerInfo*)(peer->data))->adminLevel == 1337) {
		if (((PlayerInfo*)(peer->data))->isGhost == true) {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`aHIDDEN`o> " + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
		}
		else {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`w" + name + "`o> `5" + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`5" + message), 0));
		}
	}
	else if (((PlayerInfo*)(peer->data))->adminLevel == 999) {
		if (((PlayerInfo*)(peer->data))->isGhost == true) {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`aHIDDEN`o> " + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
		}
		else {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`w" + name + "`o> `6" + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`6" + message), 0));
		}
	}
	else if (((PlayerInfo*)(peer->data))->adminLevel == 777) {
		if (((PlayerInfo*)(peer->data))->isGhost == true) {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`aHIDDEN`o> " + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
		}
		else {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`w" + name + "`o> `&" + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`&" + message), 0));
		}
	}
	else if (((PlayerInfo*)(peer->data))->adminLevel == 666) {
		if (((PlayerInfo*)(peer->data))->isGhost == true) {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`aHIDDEN`o> " + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
		}
		else {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`w" + name + "`o> `^" + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`e" + message), 0));
		}
	}
	else if (((PlayerInfo*)(peer->data))->adminLevel == 444) {
		if (((PlayerInfo*)(peer->data))->isGhost == true) {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`aHIDDEN`o> " + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
		}
		else {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`w" + name + "`o> `^" + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`^" + message), 0));
		}
	}
	else if (((PlayerInfo*)(peer->data))->adminLevel == 111) {
		if (((PlayerInfo*)(peer->data))->isGhost == true) {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`aHIDDEN`o> " + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
		}
		else {
			p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`w" + name + "`o> `!" + message));
			p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), "`!" + message), 0));
		}
	}
	else {
		p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:_PL:0_OID:_CT:[W]_ `o<`w" + name + "`o> " + message));
		p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), netID), message), 0));
	}
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{

			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet);

			//enet_host_flush(server);

			ENetPacket* packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(currentPeer, 0, packet2);

			//enet_host_flush(server);
		}
	}
	delete p.data;
	delete p2.data;
}
void showWrong(ENetPeer* peer, string listFull, string itemFind) {
	GamePacket fff = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFind item: " + itemFind + "``|left|3802|\nadd_spacer|small|\n" + listFull + "add_textbox|Enter a word below to find the item|\nadd_text_input|item|Item Name||30|\nend_dialog|findid|Cancel|Find the item!|\n"));
	ENetPacket* packetd = enet_packet_create(fff.data,
		fff.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packetd);

	//enet_host_flush(server);
	delete fff.data;
}
void sendWho(ENetPeer* peer)
{
	ENetPeer* currentPeer;
	string name = "";
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			if (((PlayerInfo*)(currentPeer->data))->isGhost)
				continue;
			GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(currentPeer->data))->netID), ((PlayerInfo*)(currentPeer->data))->displayName), 1));
			ENetPacket* packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(peer, 0, packet2);
			delete p2.data;
			//enet_host_flush(server);
		}
	}
}
void sendPuncheffect(ENetPeer* peer) {
	//return; // TODO
	PlayerInfo* info = ((PlayerInfo*)(peer->data));
	int netID = info->netID;
	ENetPeer* currentPeer;
	int state = getState(info);
	int pro = getState(info);
	int statey = 0;
	if (info->cloth_hand == 6028) statey = 1024;
	if (info->cloth_hand == 6262) statey = 8192;
	if (info->haveGrowId == false) statey = 50000;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {


			PlayerMoving data;
			data.packetType = 0x14;
			data.characterState = statey;
			data.x = 1000;
			data.y = 100;
			data.punchX = 0;
			data.punchY = 0;
			data.XSpeed = 300;
			data.YSpeed = 600;
			data.netID = netID;
			data.plantingTree = state;
			BYTE* raw = packPlayerMoving(&data);
			int var = info->peffect; // punch effect
			memcpy(raw + 1, &var, 3);
			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);


		}

	}
	// TODO 
}
void sendGazette(ENetPeer* peer) {
	std::ifstream news("news.txt");
	std::stringstream buffer;
	buffer << news.rdbuf();
	std::string newsString(buffer.str());
	GamePacket p8 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), newsString));

	ENetPacket* packet8 = enet_packet_create(p8.data,
		p8.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet8);

	//enet_host_flush(server);
	delete p8.data;

}
void sendAction(ENetPeer* peer, int netID, string action)
{
	ENetPeer* currentPeer;
	string name = "";
	GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnAction"), action));
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {

			memcpy(p2.data + 8, &netID, 4);
			ENetPacket* packet2 = enet_packet_create(p2.data,
				p2.len,
				ENET_PACKET_FLAG_RELIABLE);

			enet_peer_send(currentPeer, 0, packet2);

			//enet_host_flush(server);
		}
	}
	delete p2.data;
}


// droping items WorldObjectMap::HandlePacke

void sendModSpawn(ENetPeer* peer, int netID, int x, int y, int item, int count, BYTE specialEffect)
{
	if (item >= 7068) return;
	if (item < 0) return;
	ENetPeer* currentPeer;
	string name = "";
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			PlayerMoving data;
			data.packetType = 14;
			data.x = x;
			data.y = y;
			data.netID = netID;
			data.plantingTree = item;
			float val = count; // item count
			BYTE val2 = specialEffect;

			BYTE* raw = packPlayerMoving(&data);
			memcpy(raw + 16, &val, 4);
			memcpy(raw + 1, &val2, 1);

			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
}

void getAutoEffect(ENetPeer* peer) {
	PlayerInfo* info = ((PlayerInfo*)(peer->data));
    if (info->cloth_hand == 5480) {
		info->peffect = 8421456;
		craftItemText();
	}
	else if (info->cloth_face == 1204) {
		info->peffect = 8421386;
		craftItemText();
	}
	else if (info->cloth_face == 138) {
		info->peffect = 8421377;
		craftItemText();
	}
	else if (info->cloth_face == 2476) {
		info->peffect = 8421415;
		craftItemText();
	}
	else if (info->cloth_hand == 366 || info->cloth_hand == 1464) {
		info->peffect = 8421378;
		craftItemText();
	}
	else if (info->cloth_hand == 472) {
		info->peffect = 8421379;
		craftItemText();
	}
	else if (info->cloth_hand == 7912) {
		info->peffect = 8421487;
		craftItemText();
	}
	else if (info->cloth_hand == 594) {
		info->peffect = 8421380;
		craftItemText();
	}
	else if (info->cloth_hand == 768) {
		info->peffect = 8421381;
		craftItemText();
	}
	else if (info->cloth_hand == 900) {
		info->peffect = 8421382;
		craftItemText();
	}
	else if (info->cloth_hand == 910) {
		info->peffect = 8421383;
		craftItemText();
	}
	else if (info->cloth_hand == 930) {
		info->peffect = 8421384;
		craftItemText();
	}
	else if (info->cloth_hand == 1016) {
		info->peffect = 8421385;
		craftItemText();
	}
	else if (info->cloth_hand == 1378) {
		info->peffect = 8421387;
		craftItemText();
	}
	else if (info->cloth_hand == 1484) {
		info->peffect = 8421389;
		craftItemText();
	}
	else if (info->cloth_hand == 1512) {
		info->peffect = 8421390;
		craftItemText();
	}
	else if (info->cloth_hand == 1542) {
		info->peffect = 8421391;
		craftItemText();
	}
	else if (info->cloth_hand == 1576) {
		info->peffect = 8421392;
		craftItemText();
	}
	else if (info->cloth_hand == 1676) {
		info->peffect = 8421393;
		craftItemText();
	}
	else if (info->cloth_hand == 1710) {
		info->peffect = 8421394;
		craftItemText();
	}
	else if (info->cloth_hand == 1748) {
		info->peffect = 8421395;
		craftItemText();
	}
	else if (info->cloth_hand == 1780) {
		info->peffect = 8421396;
		craftItemText();
	}
	else if (info->cloth_hand == 1782) {
		info->peffect = 8421397;
		craftItemText();
	}
	else if (info->cloth_hand == 1804) {
		info->peffect = 8421398;
		craftItemText();
	}
	else if (info->cloth_hand == 1868) {
		info->peffect = 8421399;
		craftItemText();
	}
	else if (info->cloth_hand == 1874) {
		info->peffect = 8421400;
		craftItemText();
	}
	else if (info->cloth_hand == 1946) {
		info->peffect = 8421401;
		craftItemText();
	}
	else if (info->cloth_hand == 1948) {
		info->peffect = 8421402;
		craftItemText();
	}
	else if (info->cloth_hand == 1956) {
		info->peffect = 8421403;
		craftItemText();
	}
	else if (info->cloth_hand == 2908) {
		info->peffect = 8421405;
		craftItemText();
	}
	else if (info->cloth_hand == 2952) {
		info->peffect = 8421405;
		craftItemText();
	}
	else if (info->cloth_hand == 6312) {
		info->peffect = 8421405;
		craftItemText();
	}
	else if (info->cloth_hand == 1980) {
		info->peffect = 8421406;
		craftItemText();
	}
	else if (info->cloth_hand == 2066) {
		info->peffect = 8421407;
		craftItemText();
	}
	else if (info->cloth_hand == 2212) {
		info->peffect = 8421408;
		craftItemText();
	}
	else if (info->cloth_hand == 2218) {
		info->peffect = 8421409;
		craftItemText();
	}
	else if (info->cloth_feet == 2220) {
		info->peffect = 8421410;
		craftItemText();
	}
	else if (info->cloth_hand == 2266) {
		info->peffect = 8421411;
		craftItemText();
	}
	else if (info->cloth_hand == 2386) {
		info->peffect = 8421412;
		craftItemText();
	}
	else if (info->cloth_hand == 2388) {
		info->peffect = 8421413;
		craftItemText();
	}
	else if (info->cloth_hand == 2450) {
		info->peffect = 8421414;
		craftItemText();
	}
	else if (info->cloth_hand == 2512) {
		info->peffect = 8421417;
		craftItemText();
	}
	else if (info->cloth_hand == 2572) {
		info->peffect = 8421418;
		craftItemText();
	}
	else if (info->cloth_hand == 2592) {
		info->peffect = 8421419;
		craftItemText();
	}
	else if (info->cloth_hand == 2720) {
		info->peffect = 8421420;
		craftItemText();
	}
	else if (info->cloth_hand == 2752) {
		info->peffect = 8421421;
		craftItemText();
	}
	else if (info->cloth_hand == 2754) {
		info->peffect = 8421422;
		craftItemText();
	}
	else if (info->cloth_hand == 2756) {
		info->peffect = 8421423;
		craftItemText();
	}
	else if (info->cloth_hand == 2802) {
		info->peffect = 8421425;
		craftItemText();
	}
	else if (info->cloth_hand == 2866) {
		info->peffect = 8421426;
		craftItemText();
	}
	else if (info->cloth_hand == 2876) {
		info->peffect = 8421427;
		craftItemText();
	}
	else if (info->cloth_hand == 2886) {
		info->peffect = 8421430;
		craftItemText();
	}
	else if (info->cloth_hand == 2890) {
		info->peffect = 8421431;
		craftItemText();
	}
	else if (info->cloth_hand == 3066) {
		info->peffect = 8421433;
		craftItemText();
	}
	else if (info->cloth_hand == 3124) {
		info->peffect = 8421434;
		craftItemText();
	}
	else if (info->cloth_hand == 3168) {
		info->peffect = 8421435;
		craftItemText();
	}
	else if (info->cloth_hand == 3214) {
		info->peffect = 8421436;
		craftItemText();
	}
	else if (info->cloth_hand == 3300) {
		info->peffect = 8421440;
		craftItemText();
	}
	else if (info->cloth_hand == 3418) {
		info->peffect = 8421441;
		craftItemText();
	}
	else if (info->cloth_hand == 3476) {
		info->peffect = 8421442;
		craftItemText();
	}
	else if (info->cloth_hand == 3686) {
		info->peffect = 8421444;
		craftItemText();
	}
	else if (info->cloth_hand == 3716) {
		info->peffect = 8421445;
		craftItemText();
	}
	else if (info->cloth_hand == 4290) {
		info->peffect = 8421447;
		craftItemText();
	}
	else if (info->cloth_hand == 4474) {
		info->peffect = 8421448;
		craftItemText();
	}
	else if (info->cloth_hand == 4464) {
		info->peffect = 8421449;
		craftItemText();
	}
	else if (info->cloth_hand == 1576) {
		info->peffect = 8421450;
		craftItemText();
	}
	else if (info->cloth_hand == 4778 || info->cloth_hand == 6026) {
		info->peffect = 8421452;
		craftItemText();
	}
	else if (info->cloth_hand == 4996) {
		info->peffect = 8421453;
		craftItemText();
	}
	else if (info->cloth_hand == 4840) {
		info->peffect = 8421454;
		craftItemText();
	}
	else if (info->cloth_hand == 5480) {
		info->peffect = 8421456;
		craftItemText();
	}
	else if (info->cloth_hand == 6110) {
		info->peffect = 8421457;
		craftItemText();
	}
	else if (info->cloth_hand == 6308) {
		info->peffect = 8421458;
		craftItemText();
	}
	else if (info->cloth_hand == 6310) {
		info->peffect = 8421459;
		craftItemText();
	}
	else if (info->cloth_hand == 6298) {
		info->peffect = 8421460;
		craftItemText();
	}
	else if (info->cloth_hand == 6756) {
		info->peffect = 8421461;
		craftItemText();
	}
	else if (info->cloth_hand == 7044) {
		info->peffect = 8421462;
		craftItemText();
	}
	else if (info->cloth_shirt == 6892) {
		info->peffect = 8421463;
		craftItemText();
	}
	else if (info->cloth_hand == 7088) {
		info->peffect = 8421465;
		craftItemText();
	}
	else if (info->cloth_hand == 7098) {
		info->peffect = 8421466;
		craftItemText();
	}
	else if (info->cloth_shirt == 7192) {
		info->peffect = 8421467;
		craftItemText();
	}
	else if (info->cloth_shirt == 7136) {
		info->peffect = 8421468;
		craftItemText();
	}
	else if (info->cloth_mask == 7216) {
		info->peffect = 8421470;
		craftItemText();
	}
	else if (info->cloth_back == 7196) {
		info->peffect = 8421471;
		craftItemText();
	}
	else if (info->cloth_back == 7392) {
		info->peffect = 8421472;
		craftItemText();
	}
	else if (info->cloth_feet == 7384) {
		info->peffect = 8421474;
		craftItemText();
	}
	else if (info->cloth_hand == 7488) {
		info->peffect = 8421479;
		craftItemText();
	}
	else if (info->cloth_hand == 7586) {
		info->peffect = 8421480;
		craftItemText();
	}
	else if (info->cloth_hand == 7650) {
		info->peffect = 8421481;
		craftItemText();
	}
	else if (info->cloth_feet == 7950) {
		info->peffect = 8421489;
		craftItemText();
	}
	else if (info->cloth_hand == 8036) {
		info->peffect = 8421494;
		craftItemText();
	}
	else if (info->cloth_hand == 8910) {
		info->peffect = 8421505;
		craftItemText();
	}
	else if (info->cloth_hand == 8942) {
		info->peffect = 8421506;
		craftItemText();
	}
	else if (info->cloth_hand == 8948) {
		info->peffect = 8421507;
		craftItemText();
	}
	else if (info->cloth_hand == 8946) {
		info->peffect = 8421509;
		craftItemText();
	}
	else if (info->cloth_back == 9006) {
		info->peffect = 8421511;
		craftItemText();
	}
	else if (info->cloth_hand == 9116 || info->cloth_hand == 9118 || info->cloth_hand == 9120 || info->cloth_hand == 9122) {
	info->peffect = 8421376 + 111;
	craftItemText();
	}
	else {
		info->peffect = 8421376;
		craftItemText();
	}
}



void sendWorldOffers(ENetPeer* peer)
{
	if (!((PlayerInfo*)(peer->data))->isIn) return;
	vector<WorldInfo> worlds = worldDB.getRandomWorlds();
	string worldOffers = "default|";
	if (worlds.size() > 0) {
		worldOffers += worlds[0].name;
	}

	worldOffers += "\nadd_button|Showing: Worlds``|_catselect_|0.6|4278190335|\n";
	for (int i = 0; i < worlds.size(); i++) {
		worldOffers += "add_floater|" + worlds[i].name + "|" + std::to_string(getPlayersCountInWorld(worlds[i].name)) + "|0.55|3529161471\n";
	}
	worldOffers += "add_floater|START|0.5||4288190335\n";
	//GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
	//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
	GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), worldOffers));
	ENetPacket* packet3 = enet_packet_create(p3.data,
		p3.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet3);
	delete p3.data;
	//enet_host_flush(server);
}
void sendDialog(ENetPeer* peer, string message) {
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), message));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}
void sendPlayerToWorld(ENetPeer* peer, PlayerInfo* player, string wrldname, int x_ = -1, int y_ = -1)
{




	toUpperCase(wrldname);
	if (wrldname == "CON" || wrldname == "NUL" || wrldname == "PRN" || wrldname == "AUX" || wrldname == "CLOCK$" || wrldname == "COM0" || wrldname == "COM1" || wrldname == "COM2" || wrldname == "COM3" || wrldname == "COM4" || wrldname == "COM5" || wrldname == "COM6" || wrldname == "COM7" || wrldname == "COM8" || wrldname == "COM9" || wrldname == "LPT0" || wrldname == "LPT1" || wrldname == "LPT2" || wrldname == "LPT3" || wrldname == "LPT4" || wrldname == "LPT5" || wrldname == "LPT6" || wrldname == "LPT7" || wrldname == "LPT8" || wrldname == "LPT9")
	{
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `eWhoops! `wThis `oworld`w can't be warped to, as it is used by `4System`w.``"));
		ENetPacket* packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);

		delete p.data;
	}
	else
	{
		{
			sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
		}

		WorldInfo info = worldDB.get(wrldname);
		sendWorld(peer, &info);



		int x = 3040;
		int y = 736;


		for (int j = 0; j < info.width * info.height; j++)
		{
			if (info.items[j].foreground == 6) {
				x = (j % info.width) * 32;
				y = (j / info.width) * 32;
			}
		}
		if (x_ != -1 && y_ != -1) { x = x_ * 32; y = y_ * 32; }
		int uid = ((PlayerInfo*)(peer->data))->userID;
		GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnSpawn"), "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + std::to_string(uid) + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|0\nmstate|0\nsmstate|0\ntype|local\n"));


		ENetPacket* packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);


		delete p.data;
		((PlayerInfo*)(peer->data))->netID = cId;
		onPeerConnect(peer);
		cId++;


		sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);




	}
}
void DoCancelTransitionAndTeleport(ENetPeer* peer, int x, int y)
{
	GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnZoomCamera"), 2));
	SendGamePacket(peer, &p);
	GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
	memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
	SendGamePacket(peer, &p2);
	GamePacket p3 = packetEnd(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
	SendGamePacket(peer, &p3);
	GamePacket p4 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x * 32, y * 32));
	memcpy(p4.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
	SendGamePacket(peer, &p4);
}

void DoEnterDoor(ENetPeer* peer, WorldInfo* world, int x, int y)
{
	int idx = x + world->width * y;
	//// First determine door data
	//if (world->blocks[idx].blockData == NULL)
	//{
	//	// fail
	//	DoCancelTransitionAndTeleport(peer, x, y);
	//}
	//else if (world->blocks[idx].blockData->type != 2)
	//{
	//	// fail
	//	DoCancelTransitionAndTeleport(peer, x, y);
	//}
	//else
	{
		WorldItem block = world->items[idx];
		if (block.destWorld == "EXIT")
		{
			// fail
			sendPlayerLeave(peer, ((PlayerInfo*)(peer->data)));
			sendWorldOffers(peer); // this essentially acts just like a Main Door would
		}
		if (block.destWorld == "")
		{
			// it's this world, find a door here
			int x = 0;
			int y = 0;
			for (int i = 0; i < world->width * world->height; i++)
			{
				ItemDefinition def = getItemDef(world->items[i].foreground);
				if (def.blockType == BlockTypes::DOOR) {
					WorldItem blockDest = world->items[i];
					if (blockDest.currId == block.destId)
					{
						x = (i % world->width);
						y = (i / world->width);
						DoCancelTransitionAndTeleport(peer, x, y);
						return;
					}
				}
			}
			x = 0;
			y = 0;

			for (int j = 0; j < world->width * world->height; j++)
			{
				if (world->items[j].foreground == 6) {
					x = (j % world->width);
					y = (j / world->width);
				}
			}
			DoCancelTransitionAndTeleport(peer, x, y);
		}
		else
		{
			try
			{
				WorldInfo worldDest = worldDB.get(block.destWorld);
				if (block.destId == "")
				{
					int x_ = 0;
					int y_ = 0;

					for (int j = 0; j < worldDest.width * worldDest.height; j++)
					{
						if (worldDest.items[j].foreground == 6) {
							x_ = (j % worldDest.width);
							y_ = (j / worldDest.width);
						}
					}
					sendPlayerToWorld(peer, ((PlayerInfo*)(peer->data)), block.destWorld, x_, y_);
					return;
				}
				else
				{
					int x_ = 0;
					int y_ = 0;
					bool found = false;
					for (int i = 0; i < worldDest.width * worldDest.height; i++)
					{
						ItemDefinition def = getItemDef(worldDest.items[i].foreground);
						if (def.blockType == BlockTypes::DOOR) {
							WorldItem blockDest = worldDest.items[i];
							if (block.currId == blockDest.destId)
							{
								x_ = (i % world->width);
								y_ = (i / world->width);
								sendPlayerToWorld(peer, ((PlayerInfo*)(peer->data)), block.destWorld, x_, y_);
								found = true;
								break;
							}
						}
					}
					if (!found)
					{
						int x = 0;
						int y = 0;

						for (int j = 0; j < worldDest.width * worldDest.height; j++)
						{
							if (worldDest.items[j].foreground == 6) {
								x = (j % worldDest.width);
								y = (j / worldDest.width);
							}
						}
						sendPlayerToWorld(peer, ((PlayerInfo*)(peer->data)), block.destWorld, x, y);
					}
				}
			}
			catch (int e)
			{
				DoCancelTransitionAndTeleport(peer, x, y);
				sendChatMessage(peer, (((PlayerInfo*)(peer->data))->netID), "That door can't lead to such an awesome place!");
			}
		}
	}
	GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetFreezeState"), 0));
	memcpy(p5.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
	ENetPacket* packet5 = enet_packet_create(p5.data,
		p5.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet5);
	enet_host_flush(server);

	GamePacket p4 = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
	ENetPacket* packet4 = enet_packet_create(p4.data,
		p4.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet4);
	enet_host_flush(server);
}




//replaced X-to-close with a Ctrl+C exit
void exitHandler(int s) {
	saveAllWorlds();
	exit(0);

}

bool has_only_digits(const string s) {
	return s.find_first_not_of("0123456789") == string::npos;
}
bool has_only_digits_wnegative(const string s) {
	return s.find_first_not_of("-0123456789") == string::npos;
}
std::ifstream::pos_type filesize(const char* filename)
{
	std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
	return in.tellg();
}

uint32_t HashString(unsigned char* str, int len)
{
	if (!str) return 0;

	unsigned char* n = (unsigned char*)str;
	uint32_t acc = 0x55555555;

	if (len == 0)
	{
		while (*n)
			acc = (acc >> 27) + (acc << 5) + *n++;
	}
	else
	{
		for (int i = 0; i < len; i++)
		{
			acc = (acc >> 27) + (acc << 5) + *n++;
		}
	}
	return acc;

}

unsigned char* getA(string fileName, int* pSizeOut, bool bAddBasePath, bool bAutoDecompress)
{
	unsigned char* pData = NULL;
	FILE* fp = fopen(fileName.c_str(), "rb");
	if (!fp)
	{
		cout << "[!] File not found" << endl;
		if (!fp) return NULL;
	}

	fseek(fp, 0, SEEK_END);
	*pSizeOut = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	pData = (unsigned char*)new unsigned char[((*pSizeOut) + 1)];
	if (!pData)
	{
		printf("Out of memory opening %s?", fileName.c_str());
		return 0;
	}
	pData[*pSizeOut] = 0;
	fread(pData, *pSizeOut, 1, fp);
	fclose(fp);

	return pData;
}

struct itemDataStruct {
	string name;
	string texturefile;
	string audiofile;
	int id;
	uint8_t editableType;
	uint8_t category;
	uint8_t type;
	uint8_t solid;
	uint16_t rarity;
	uint32_t color1;
	uint32_t color2;
	uint8_t textureX;
	uint8_t textureY;
	uint8_t textureType;
	uint8_t hardness;
	uint16_t audioVol;
	uint32_t texturehash;
	uint32_t audiohash;
	uint8_t seedBase;
	uint8_t seedOverlay;
	uint8_t treeBase;
	uint8_t treeOverlay;
};

void decodeName(char* src, int len, int itemID, char* dest) {
	const char key[] = "PBG892FXX982ABC*";
	for (int i = 0; i < len; i++) {
		dest[i] = src[i] ^ key[(i + itemID) % 16];
	}
}

vector<itemDataStruct> items;
itemDataStruct getItem(int id) {
	if (itemsDat == NULL) {
		itemDataStruct ret;
		ret.id = -1;
		return ret;
	}
	uint8_t* itemsPtr = itemsDat + 60;
	itemsPtr += 4;
	while (true) {
		itemsPtr += *(uint16_t*)itemsPtr + 2;

		if (*(uint16_t*)itemsPtr == id) {
			itemDataStruct item;

			item.id = *(uint16_t*)itemsPtr;
			itemsPtr += 2;

			itemsPtr += 2; // ??

			item.editableType = *(uint8_t*)itemsPtr++;
			item.category = *(uint8_t*)itemsPtr++;
			item.type = *(uint8_t*)itemsPtr++;
			itemsPtr++;

			int nameLen = *(uint16_t*)itemsPtr;
			itemsPtr += 2;
			string name;
			name.resize(nameLen);
			decodeName((char*)itemsPtr, nameLen, id, &name[0]);
			item.name = name;
			itemsPtr += nameLen;

			int textureLen = *(uint16_t*)itemsPtr;
			itemsPtr += 2;
			string texturefile;
			texturefile.resize(textureLen);
			memcpy(&texturefile[0], itemsPtr, textureLen);
			item.texturefile = texturefile;
			itemsPtr += textureLen;

			item.texturehash = *(uint32_t*)itemsPtr;
			itemsPtr += 4;

			itemsPtr += 5; // ??

			item.textureX = *(uint8_t*)itemsPtr++;
			item.textureY = *(uint8_t*)itemsPtr++;
			item.textureType = *(uint8_t*)itemsPtr;
			itemsPtr += 2;

			item.solid = *(uint8_t*)itemsPtr++;

			item.hardness = *(uint8_t*)itemsPtr++;

			itemsPtr += 1; // mystery_3
			itemsPtr += 4; // ??

			item.rarity = *(uint16_t*)itemsPtr;
			itemsPtr += 2;

			itemsPtr += 1; // ??

			int audioLen = *(uint16_t*)itemsPtr;
			itemsPtr += 2;
			string audiofile;
			audiofile.resize(audioLen);
			memcpy(&audiofile[0], itemsPtr, audioLen);
			item.audiofile = audiofile;
			itemsPtr += audioLen;

			item.audiohash = *(uint32_t*)itemsPtr;
			itemsPtr += 4;
			item.audioVol = *(uint16_t*)itemsPtr;
			itemsPtr += 2;

			itemsPtr += 16; // ??

			item.seedBase = *(uint8_t*)itemsPtr++;
			item.seedOverlay = *(uint8_t*)itemsPtr++;
			item.treeBase = *(uint8_t*)itemsPtr++;
			item.treeOverlay = *(uint8_t*)itemsPtr++;

			item.color1 = *(uint32_t*)itemsPtr;
			itemsPtr += 4;
			item.color2 = *(uint32_t*)itemsPtr;
			itemsPtr += 4;

			return item;
		}
		else {
			itemsPtr += 8;
			itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += 23;
			itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += 8;
			for (int i = 0; i < 4; i++) itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += 24;
			itemsPtr += *(uint16_t*)itemsPtr + 2; // not sure about this
			itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += *(uint16_t*)itemsPtr + 2;
			itemsPtr += 78;
		}

		if (itemsPtr - itemsDat >= itemsDatSize) {
			itemDataStruct item;
			item.id = -1;
			return item;
		}
	}
}
void serializeItems() {
	printf("Loading all items...saveallworlds\n");
	int i = 0;
	while (true) {
		itemDataStruct item = getItem(i++);
		if (item.id == -1) break;
		items.push_back(item);
	}
	printf("Finished loading all items...\n");
}
void commands()
{
	while (commands)
	{
		std::string input;
		std::cin >> input;


		if (input == "exit")
		{
			saveAllWorlds();
			exit(0);
		}
		else if (input == "save") {
			saveAllWorlds();
		}
		else if (input == "online")
		{
			string x;


			ENetPeer* currentPeer;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;


				x.append(((PlayerInfo*)(currentPeer->data))->rawName + " (" + to_string(((PlayerInfo*)(currentPeer->data))->adminLevel) + ")" + " (" + ((PlayerInfo*)(currentPeer->data))->charIP + ")" + ", ");
			}
			x = x.substr(0, x.length() - 2);

			cout << "[!] [Console] Peers connected (includes mods) [format: (rawname) (adminlevel) (IP)]: " << x << endl;

		}
		else if (input == "kickall")
		{
			ENetPeer* currentPeer;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;

				enet_peer_disconnect_later(currentPeer, 0);
				enet_peer_reset(currentPeer);
			}
			cout << "[!] Kicked everyone out of server!" << endl;
		}
		else if (input == "help" || input == "?")
		{
			cout << "[!] Operator commands: " << "help " << "kickall " << "save " << "reload" << "online " << "delete " << "maintenance " << "exit" << endl;
		}
		else {
			cout << "[!] Unknown command, type /help to see list of valid commands." << endl;
		}
	}
}

void loadConfig()
{

	cout << "[!] loading config" << endl;
	std::ifstream ifs("config.json");
	if (ifs.is_open()) {


		json j;
		ifs >> j;

		configPort = j["Port"];
		music = j["Music"].get<string>();

		cout << "[~] Config loaded." << endl;
		cout << "[-] Hosting on Port: " << configPort << endl;
		cout << "[!] Music theme: " << music << endl;



	}




	ifs.close();
	// finished
}
void sendConsole(ENetPeer * x, string e) {
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), e));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(x, 0, packet);
	delete p.data;
}
/*
action|log
msg|`4UPDATE REQUIRED!`` : The `$V2.981`` update is now available for your device.  Go get it!  You'll need to install it before you can play online.
[DBG] Some text is here: action|set_url
url|http://ubistatic-a.akamaihd.net/0098/20180909/Growtalestaller.exe
label|Download Latest Version
	*/
	//Linux should not have any arguments in main function.
#ifdef _WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif
{
	cout << "[!] Growtale Server (C) Senpai Tyzies Mindpin & GrowtopiaNoobs" << endl;
	cout << "[!] Growtale is Running" << endl;
	cout << "[~] Server Up Time: " + currentDateTime() + "!" << endl;
	cout << "[!] Auto save worlds loaded!" << endl;
	loadConfig();
	std::ifstream t("totaluids.txt");
	std::string str((std::istreambuf_iterator<char>(t)),
		std::istreambuf_iterator<char>());
	totaluserids = atoi(str.c_str());
	enet_initialize();
	//Unnecessary save at exit. Commented out to make the program exit slightly quicker.
	if (atexit(saveAllWorlds)) {
		cout << "Worlds won't be saved for this session..." << endl;
	}
	/*if (RegisterApplicationRestart(L" -restarted", 0) == S_OK)
	{
		cout << "Autorestart is ready" << endl;
	}
	else {
		cout << "Binding autorestart failed!" << endl;
	}
	Sleep(65000);
	int* p = NULL;
	*p = 5;*/
	int itemdathash;
	{
		std::ifstream file("items.dat", std::ios::binary | std::ios::ate);
		itemsDatSize = file.tellg();
		itemsDat = new BYTE[60 + itemsDatSize];
		string asdf = "0400000010000000FFFFFFFF000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
		for (int i = 0; i < asdf.length(); i += 2)
		{
			char x = ch2n(asdf[i]);
			x = x << 4;
			x += ch2n(asdf[i + 1]);
			memcpy(itemsDat + (i / 2), &x, 1);
			if (asdf.length() > 60 * 2) throw 0;
		}
		memcpy(itemsDat + 56, &itemsDatSize, 4);
		file.seekg(0, std::ios::beg);

		if (file.read((char*)(itemsDat + 60), itemsDatSize))
		{
			uint8_t* pData;
			int size = 0;
			const char filename[] = "items.dat";
			size = filesize(filename);
			pData = getA((string)filename, &size, false, false);
			cout << "[+] Items.dat reloaded! Hash: " << HashString((unsigned char*)pData, size) << endl;
			itemdathash = HashString((unsigned char*)pData, size);
			file.close();
			//serializeItems();

		}
		else {
			cout << "[-] No items.dat found!" << endl;
		}
	}


	//world = generateWorld();
	ENetAddress address;
	/* Bind the server to the default localhost.     */
	/* A specific host address can be specified by   */
	enet_address_set_host(&address, "0.0.0.0");
	//address.host = ENET_HOSconT_ANY;
	/* Bind the server to port 1234. */
	address.port =  configPort;
	server = enet_host_create(&address /* the address to bind the server host to */,
		1024      /* allow up to 32 clients and/or outgoing connections */,
		10      /* allow up to 2 channels to be used, 0 and 1 */,
		0      /* assume any amount of incoming bandwidth */,
		0      /* assume any amount of outgoing bandwidth */);
	if (server == NULL)
	{
		fprintf(stderr,
			"An error occurred while trying to create an ENet server host.\n");
		while (1);
		exit(EXIT_FAILURE);
	}
	server->checksum = enet_crc32;
	enet_host_compress_with_range_coder(server);

	BuildItemsDatabase();
	cout << "[!] Server database builded!" << endl;
	/*cout << "Items.dat serialized! Loaded items: " << items.size() << endl;
	ofstream decompile;
	decompile.open("itemsdatdecompiled.txt", std::ios_base::app);
	for (int i = 0; i < items.size(); i++) {
		//cout << "Decompiling items.dat at id: " << items[i].id << " with name: " << items[i].name << endl;
		decompile << "name|" << items[i].name << endl;
		decompile << "audiofile|" << items[i].audiofile << endl;
		decompile << "id|" << items[i].id << endl;
		decompile << "editableType|" << items[i].editableType << endl;
		decompile << "itemCategory|" << items[i].category << endl;
		decompile << "actionType|" << items[i].type << endl;
		decompile << "solid|" << items[i].solid << endl;
		decompile << "color1|" << items[i].color1 << endl;
		decompile << "color2|" << items[i].color2 << endl;
		decompile << "textureX|" << items[i].textureX << endl;
		decompile << "textureY|" << items[i].textureY << endl;
		decompile << "textureType|" << items[i].textureType << endl;
		decompile << "hardness|" << items[i].hardness << endl;
		decompile << "audioVol|" << items[i].audioVol << endl;
		decompile << "texturehash|" << items[i].texturehash << endl;
		decompile << "audiohash|" << items[i].audiohash << endl;
		decompile << "seedBase|" << items[i].seedBase << endl;
		decompile << "seedOverlay|" << items[i].seedOverlay << endl;
		decompile << "treeBase|" << items[i].treeBase << endl;
		decompile << "treeOverlay|" << items[i].treeOverlay << endl;
		decompile << "\n";
	}
	decompile.close();*/

	ENetEvent event;
	/* Wait up to 1000 milliseconds for an event. */
	while (true)
		while (enet_host_service(server, &event, 1000) > 0)
		{
			ENetPeer* peer = event.peer;
			if (!peer) continue;
			switch (event.type)
			{
			case ENET_EVENT_TYPE_CONNECT:
			{
#ifdef TOTAL_LOG
				printf("A new client connected.\n");
#endif

				/* Store any relevant client information here. */
				//event.peer->data = "Client information";
				if (getPlayersCountInServer() >= 220) {
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4OOPS: `oServer is at MAX capacity. Please click `5CANCEL `oand try again in a few seconds.``"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					enet_peer_disconnect_later(peer, 0);
				}
				ENetPeer* currentPeer;
				int count = 0;
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (currentPeer->address.host == peer->address.host)
						count++;
				}
				event.peer->data = new PlayerInfo;
				/* Get the string ip from peer */
				char clientConnection[16];
				enet_address_get_host_ip(&peer->address, clientConnection, 16);
				((PlayerInfo*)(peer->data))->charIP = clientConnection;
				if (count > 3)
				{
					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `rToo many accounts are logged on from this IP. Log off one account before playing please.``"));
					ENetPacket* packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(peer, 0, packet);
					delete p.data;
					//enet_host_flush(server);
					enet_peer_disconnect_later(peer, 0);
				}
				else {
					sendData(peer, 1, 0, 0);
				}


				continue;
			}
			case ENET_EVENT_TYPE_RECEIVE:
			{
				if (event.packet->dataLength > 4096) {
					enet_peer_reset(peer);
					continue;
				}
				if (std::find(bannedlist.begin(), bannedlist.end(), ((PlayerInfo*)(peer->data))->tankIDName) != bannedlist.end())
				{
					sendLogonFail(peer, "`oSorry, but`w " + ((PlayerInfo*)(peer->data))->tankIDName + "`o account is `4Banned`o! If you have some questions please Contact Us at Discord!");
					enet_peer_disconnect_later(peer, 0);
				}
				if ((char)event.packet->data == '\xFF') {
					Player::OnConsoleMessage(peer, "`oIf you see this contact the developer!");
					continue;
				}
				if (((PlayerInfo*)(peer->data))->isUpdating)
				{
					cout << "[!] packet drop" << endl;
					continue;
				}
				int messageType = GetMessageTypeFromPacket(event.packet);
				//cout << "[!] Packet type is " << messageType << endl;
				//cout << (event->packet->data+4) << endl;
				WorldInfo* world = getPlyersWorld(peer);
				switch (messageType) {
				case 2:
				{
					string cch = GetTextPointerFromPacket(event.packet);

					if (cch.length() > 500)
					{
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Oh No! something is wrong and you will be disconnected..."));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
						enet_peer_disconnect_later(peer, 0);
					}
					string str = cch.substr(cch.find("text|") + 5, cch.length() - cch.find("text|") - 1);
					if (cch.find("action|wrench") == 0) {
						vector<string> ex = explode("|", cch);


						stringstream ss;


						ss << ex[3];


						string temp;
						int found;
						while (!ss.eof()) {


							ss >> temp;


							if (stringstream(temp) >> found)
								//cout << found;
								((PlayerInfo*)(peer->data))->wrenchsession = found;


							temp = "";
						}
						string worldsowned;
						string rolex;
						string rolexx;
						if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
							continue;
						}
						if (((PlayerInfo*)(peer->data))->isNicked == true) {
							continue;
						}
						ENetPeer* currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;


							if (isHere(peer, currentPeer)) {
								if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) {
									continue;
								}
								if (((PlayerInfo*)(currentPeer->data))->isNicked == true) {
									continue;
								}
								if (((PlayerInfo*)(currentPeer->data))->netID == ((PlayerInfo*)(peer->data))->wrenchsession) {

									((PlayerInfo*)(peer->data))->lastInfo = ((PlayerInfo*)(currentPeer->data))->rawName;
									((PlayerInfo*)(peer->data))->lastInfoname = ((PlayerInfo*)(currentPeer->data))->tankIDName;

									string name = ((PlayerInfo*)(currentPeer->data))->displayName;
									string rawnam = ((PlayerInfo*)(peer->data))->rawName;
									string rawnamofwrench = ((PlayerInfo*)(currentPeer->data))->rawName;
									string gems = std::to_string(((PlayerInfo*)(currentPeer->data))->gem);
									string token = std::to_string(((PlayerInfo*)(currentPeer->data))->wls);
									string guildleader = ((PlayerInfo*)(peer->data))->guildLeader;
									if (rawnamofwrench != rawnam)
									{

										if (rawnamofwrench != "")
										{
											if (find(((PlayerInfo*)(peer->data))->guildMembers.begin(), ((PlayerInfo*)(peer->data))->guildMembers.end(), name) != ((PlayerInfo*)(peer->data))->guildMembers.end()) {
												if (world->owner == ((PlayerInfo*)(peer->data))->rawName && ((PlayerInfo*)(peer->data))->haveGrowId || ((PlayerInfo*)(peer->data))->adminLevel >= 777)
												{
													if (((PlayerInfo*)(peer->data))->adminLevel >= 999 || ((PlayerInfo*)(peer->data))->rawName == "mindpin")
													{
														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`w" + name + " `w(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`w)``|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wMoney : `6" + gems + "$|left|4|\nadd_label|small|`wGrowtale Token : `2" + token + "$|left|4|\nadd_label|small|`wRank:|left|4|\nadd_label_with_icon|small|" + getRankText(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wLevel Rank:|left|4|\nadd_label_with_icon|small|" + getRankTexts(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankIds(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|\nadd_button|trades|`9Trade|0|0|\nadd_button|infobutton|`!Punish/View|0|0|\nadd_button|pull|`5Pull|0|0|\nadd_button|kick|`4Kick|0|0|\nadd_button|wban|`4World Ban|0|0|\nadd_button|giveownership|`wGive ownership to this player!|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));
														ENetPacket* packet = enet_packet_create(p.data,
															p.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet);
														delete p.data;
													}
													else
													{
														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + " `w(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`w)``|left|18|\nadd_spacer|small|\nadd_label|small|`wMoney : `6" + gems + "$|left|4|\nadd_label|small|`wGrowtale Token = `2" + token + "$|left|4|\nadd_label|small|`wRank:|left|4|\nadd_label_with_icon|small|" + getRankText(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wLevel Rank:|left|4|\nadd_label_with_icon|small|" + getRankTexts(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankIds(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_button|trades|`wTrade|0|0|\nadd_button|pull|`5Pull|0|0|\nadd_button|kick|`4Kick|0|0|\nadd_button|wban|`4World Ban|0|0|\nadd_button|giveownership|`wGive ownership to this player!|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));
														ENetPacket* packet = enet_packet_create(p.data,
															p.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet);
														delete p.data;
													}
												}
												else
												{
													GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + " `w(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`w)``|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wMoney : `6" + gems + "$|left|4|\nadd_label|small|`wGrowtale Token = `2" + token + "$|left|4|\nadd_label|small|`wRank:|left|4|\nadd_label_with_icon|small|" + getRankText(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\n\nadd_spacer|small|\nadd_label|small|`wLevel Rank:|left|4|\nadd_label_with_icon|small|" + getRankTexts(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankIds(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_button|trades|`wTrade|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));
													ENetPacket* packet = enet_packet_create(p.data,
														p.len,
														ENET_PACKET_FLAG_RELIABLE);
													enet_peer_send(peer, 0, packet);
													delete p.data;
												}
											}
											else if (((PlayerInfo*)(peer->data))->rawName == guildleader) {
												if (world->owner == ((PlayerInfo*)(peer->data))->rawName && ((PlayerInfo*)(peer->data))->haveGrowId || ((PlayerInfo*)(peer->data))->adminLevel >= 777)
												{
													if (((PlayerInfo*)(peer->data))->adminLevel >= 999 || ((PlayerInfo*)(peer->data))->rawName == "mindpin")
													{
														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`w" + name + " `w(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`w)``|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wMoney : `6" + gems + "$|left|4|\nadd_label|small|`wGrowtale Token : `2" + token + "$|left|4|\nadd_label|small|`wRank:|left|4|\nadd_label_with_icon|small|" + getRankText(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wLevel Rank:|left|4|\nadd_label_with_icon|small|" + getRankTexts(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankIds(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|\nadd_button|trades|`9Trade|0|0|\nadd_button|infobutton|`!Punish/View|0|0|\nadd_button|pull|`5Pull|0|0|\nadd_button|kick|`4Kick|0|0|\nadd_button|wban|`4World Ban|0|0|\nadd_button|inviteguildbutton|`2Invite to guild``|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));
														ENetPacket* packet = enet_packet_create(p.data,
															p.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet);
														delete p.data;
													}
													else
													{
														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + " `w(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`w)``|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wMoney : `6" + gems + "$|left|4|\nadd_label|small|`wGrowtale Token = `2" + token + "$|left|4|\nadd_label|small|`wRank:|left|4|\nadd_label_with_icon|small|" + getRankText(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wLevel Rank:|left|4|\nadd_label_with_icon|small|" + getRankTexts(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankIds(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_button|trades|`wTrade|0|0|\nadd_button|pull|`5Pull|0|0|\nadd_button|kick|`4Kick|0|0|\nadd_button|wban|`4World Ban|0|0|\nadd_button|inviteguildbutton|`2Invite to guild``|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));
														ENetPacket* packet = enet_packet_create(p.data,
															p.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet);
														delete p.data;
													}
												}
												else
												{
													GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + " `w(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`w)``|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wMoney : `6" + gems + "$|left|4|\nadd_label|small|`wGrowtale Token = `2" + token + "$|left|4|\nadd_label|small|`wRank:|left|4|\nadd_label_with_icon|small|" + getRankText(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\n\nadd_spacer|small|\nadd_label|small|`wLevel Rank:|left|4|\nadd_label_with_icon|small|" + getRankTexts(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankIds(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_button|trades|`wTrade|0|0|\nadd_button|inviteguildbutton|`2Invite to guild``|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));
													ENetPacket* packet = enet_packet_create(p.data,
														p.len,
														ENET_PACKET_FLAG_RELIABLE);
													enet_peer_send(peer, 0, packet);
													delete p.data;
												}
											}
											else {
												if (world->owner == ((PlayerInfo*)(peer->data))->rawName && ((PlayerInfo*)(peer->data))->haveGrowId || ((PlayerInfo*)(peer->data))->adminLevel >= 777)
												{
													if (((PlayerInfo*)(peer->data))->adminLevel >= 999 || ((PlayerInfo*)(peer->data))->rawName == "mindpin")
													{
														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`w" + name + " `w(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`w)``|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wMoney : `6" + gems + "$|left|4|\nadd_label|small|`wGrowtale Token : `2" + token + "$|left|4|\nadd_label|small|`wRank:|left|4|\nadd_label_with_icon|small|" + getRankText(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wLevel Rank:|left|4|\nadd_label_with_icon|small|" + getRankTexts(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankIds(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|\nadd_button|trades|`9Trade|0|0|\nadd_button|infobutton|`!Punish/View|0|0|\nadd_button|pull|`5Pull|0|0|\nadd_button|kick|`4Kick|0|0|\nadd_button|wban|`4World Ban|0|0|\nadd_button|giveownership|`wGive ownership to this player!|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));
														ENetPacket* packet = enet_packet_create(p.data,
															p.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet);
														delete p.data;
													}
													else
													{
														GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + " `w(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`w)``|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wMoney : `6" + gems + "$|left|4|\nadd_label|small|`wGrowtale Token = `2" + token + "$|left|4|\nadd_label|small|`wRank:|left|4|\nadd_label_with_icon|small|" + getRankText(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wLevel Rank:|left|4|\nadd_label_with_icon|small|" + getRankTexts(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankIds(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_button|trades|`wTrade|0|0|\nadd_button|pull|`5Pull|0|0|\nadd_button|kick|`4Kick|0|0|\nadd_button|wban|`4World Ban|0|0|\nadd_button|giveownership|`wGive ownership to this player!|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));
														ENetPacket* packet = enet_packet_create(p.data,
															p.len,
															ENET_PACKET_FLAG_RELIABLE);
														enet_peer_send(peer, 0, packet);
														delete p.data;
													}
												}
												else
												{
													GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + " `w(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`w)``|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_label|small|`wMoney : `6" + gems + "$|left|4|\nadd_label|small|`wGrowtale Token = `2" + token + "$|left|4|\nadd_label|small|`wRank:|left|4|\nadd_label_with_icon|small|" + getRankText(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\n\nadd_spacer|small|\nadd_label|small|`wLevel Rank:|left|4|\nadd_label_with_icon|small|" + getRankTexts(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankIds(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_button|trades|`wTrade|0|0|\nadd_spacer|small|\nadd_button||Continue|0|0|\nadd_quick_exit"));
													ENetPacket* packet = enet_packet_create(p.data,
														p.len,
														ENET_PACKET_FLAG_RELIABLE);
													enet_peer_send(peer, 0, packet);
													delete p.data;
												}
											}
										}
										else
										{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_label_with_icon|big|`0" + name + " `w(`2" + to_string(((PlayerInfo*)(currentPeer->data))->level) + "`w)``|left|" + getRankId(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_button|chc0|Close|noflags|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete p.data;
										}
									}
									else
									{
										if (((PlayerInfo*)(peer->data))->haveGrowId == true)
										{
											std::ostringstream oss;
											if (!((PlayerInfo*)(peer->data))->worldsowned.empty())
											{
												std::copy(((PlayerInfo*)(peer->data))->worldsowned.begin(), ((PlayerInfo*)(peer->data))->worldsowned.end() - 1,
													std::ostream_iterator<string>(oss, " "));

												// Now add the last element with no delimiter
												oss << ((PlayerInfo*)(peer->data))->worldsowned.back();
											}
											else {
												string oss = "You dont have any worlds!";
											}
											int levels = ((PlayerInfo*)(peer->data))->level;
											int xp = ((PlayerInfo*)(peer->data))->xp;
											int diamond = ((PlayerInfo*)(peer->data))->wls;
											int rubble = ((PlayerInfo*)(peer->data))->ban;
											string currentworld = ((PlayerInfo*)(peer->data))->currentWorld;
											int yy = ((PlayerInfo*)(peer->data))->posX / 32;
											int xx = ((PlayerInfo*)(peer->data))->posY / 32;

											if (((PlayerInfo*)(peer->data))->isinvited == true)
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_player_info|" + name + "|" + std::to_string(levels) + "|" + std::to_string(xp) + "|300|\nadd_spacer|small|\nadd_button|joinguild|`2Join Guild " + ((PlayerInfo*)(currentPeer->data))->guildlast + "!|\nadd_spacer|small|\nadd_textbox|`oYou currently have `2" + to_string(((PlayerInfo*)(peer->data))->gem) + "`o$|left|\nadd_textbox|`oYou currently have `2" + to_string(rubble) + "|left|\nadd_textbox|`oYou currently have `2" + to_string(((PlayerInfo*)(peer->data))->wls) + " `oGrowtale Token|left|\nadd_spacer|small|\nadd_label|small|`wLevel Rank:|left|4|\nadd_label_with_icon|small|" + getRankTexts(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankIds(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_textbox|`oCurrent world:`w " + ((PlayerInfo*)(currentPeer->data))->currentWorld + "``(`w" + std::to_string(xx) + "``, `w" + std::to_string(yy) + "``) (`w" + std::to_string(getPlayersCountInWorld(((PlayerInfo*)(currentPeer->data))->currentWorld)) + "`` person)````|left|\nadd_textbox|`oWorlds Owned:" + oss.str() + "|left|4|\nadd_spacer|small|\nadd_button|aapmenu|`$Manage AAP|\nadd_spacer|small|\nadd_button|chc0|Close|noflags|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
												ENetPacket* packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												delete p.data;
											}
											else
											{
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_player_info|" + name + "|" + std::to_string(levels) + "|" + std::to_string(xp) + "|300|\nadd_spacer|small|\nadd_spacer|small|\nadd_button|rankinfo|`wLevel rank info|\nadd_spacer|small|\nadd_textbox|`oYou currently have `2" + to_string(((PlayerInfo*)(peer->data))->gem) + "`o$|left|\nadd_textbox|`oYou currently have `2" + to_string(rubble) + "|left|\nadd_textbox|`oYou currently have `2" + to_string(((PlayerInfo*)(peer->data))->wls) + " `oGrowtale Token|left|\nadd_spacer|small|\nadd_label|small|`wLevel Rank:|left|4|\nadd_label_with_icon|small|" + getRankTexts(((PlayerInfo*)(peer->data))->lastInfoname) + "|left|" + getRankIds(((PlayerInfo*)(peer->data))->lastInfoname) + "|\nadd_spacer|small|\nadd_textbox|`oCurrent world:`w " + ((PlayerInfo*)(currentPeer->data))->currentWorld + "``(`w" + std::to_string(xx) + "``, `w" + std::to_string(yy) + "``) (`w" + std::to_string(getPlayersCountInWorld(((PlayerInfo*)(currentPeer->data))->currentWorld)) + "`` person)````|left|\nadd_textbox|`oWorlds Owned:" + oss.str() + "|left|4|\nadd_spacer|small|\nadd_button|aapmenu|`$Manage AAP|\nadd_spacer|small|\nadd_button|chc0|Close|noflags|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
												ENetPacket* packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												delete p.data;
											}
										}
										else
										{
										}
									}

								}


							}


						}
					}
					if (cch.find("action|friends") == 0)
					{
						if (((PlayerInfo*)(peer->data))->joinguild == true) {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|showguild|Show Guild Members``|0|0|\nend_dialog||OK||\nadd_quick_exit|"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						else {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|createguildinfo|Create Guild``|0|0|\nend_dialog||OK||\nadd_quick_exit|"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
					}
					if (cch.find("action|respawn") == 0)
					{
						if (cch.find("action|respawn_spike") == 0) {
							playerRespawn(peer, true);
						}
						else
						{
							playerRespawn(peer, false);
						}
					}
					if (cch.find("action|growid") == 0)
					{
#ifndef REGISTRATION
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Registration is not supported yet!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
						}
#endif
#ifdef REGISTRATION
						//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGet a GrowID``|left|206|\n\nadd_spacer|small|\nadd_textbox|A `wGrowID `wmeans `oyou can use a name and password to logon from any device.|\nadd_spacer|small|\nadd_textbox|This `wname `owill be reserved for you and `wshown to other players`o, so choose carefully!|\nadd_text_input|username|GrowID||30|\nadd_text_input_password|password|Password||100|\nadd_text_input_password|passwordverify|Password Verify||100|\nadd_textbox|Your `wemail address `owill only be used for account verification purposes and won't be spammed or shared. If you use a fake email, you'll never be able to recover or change your password.|\nadd_text_input|email|Email||100|\nend_dialog|register|Cancel|Get My GrowID!|\n"));
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
#endif
					}
					if (cch.find("action|store") == 0)
					{
						if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|big|`wWelcome To `5Growtale `0market!|left|5016|\n\nadd_spacer|small|small|\nadd_smalltext|small|`wCurrently You have `9" + to_string(((PlayerInfo*)(peer->data))->gem) + " `wgems|left|\nadd_textbox|`wWelcome to Growtale store, if you want to purchase `2items`w, click on `wPurchase `eItems`w, if you want to buy role or gems or wls or level, click on `wPurchase `1Assets.``|left|\n\nadd_spacer|small|\nadd_button|items|`wPurchase `eItems|noflags|3233|small|left|212|\nadd_button|ingameassets|`wPurchase `1Assets|noflags|1232|small|\nadd_button|blocks|`wPurchase `9Blocks|noflags|1232|small|\nadd_button|storeinvupgrade|`wPurchase `4Inventory Upgrade|noflags|3233|\nadd_spacer|small|\nend_dialog|cl0se|Close||\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;//list to do, tugas, setup vps + coding.
						}
						else {
#ifdef REGISTRATION
							//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGet a GrowID``|left|206|\n\nadd_spacer|small|\nadd_textbox|A `wGrowID `wmeans `oyou can use a name and password to logon from any device.|\nadd_spacer|small|\nadd_textbox|This `wname `owill be reserved for you and `wshown to other players`o, so choose carefully!|\nadd_text_input|username|GrowID||30|\nadd_text_input_password|password|Password||100|\nadd_text_input_password|passwordverify|Password Verify||100|\nadd_textbox|Your `wemail address `owill only be used for account verification purposes and won't be spammed or shared. If you use a fake email, you'll never be able to recover or change your password.|\nadd_text_input|email|Email||100|\nend_dialog|register|Cancel|Get My GrowID!|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
#endif

							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `1You must create `4GrowID `1first before you can access the `2Store`1!"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
					}
					if (cch.find("action|info") == 0)
					{
						std::stringstream ss(cch);
						std::string to;
						int id = -1;
						int count = -1;
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 3) {
								if (infoDat[1] == "itemID") id = atoi(infoDat[2].c_str());
								if (infoDat[1] == "count") count = atoi(infoDat[2].c_str());
							}
						}

						if (id == -1 || count == -1) continue;
						if (itemDefs.size() < id || id < 0) continue;
						string properties = "";
						ItemDefinition itemDef = GetItemDef(id);
						if (itemDef.rarity != 999)
							properties += "add_textbox|`oRarity: `w" + to_string(itemDef.rarity) + "``|\n";
						properties += "add_spacer|small|\n";
						// find properties
						if (itemDef.properties & Property_Untradable)
							properties += "add_textbox|`1This item cannot be dropped or traded.``|\n";
						if (itemDef.properties & Property_Wrenchable)
							properties += "add_textbox|`1This item has special properties you can adjust with the Wrench.``|\n";
						if (itemDef.properties & Property_NoSeed)
							properties += "add_textbox|`1This item never drops any seeds.``|\n";
						if (itemDef.properties & Property_Permanent)
							properties += "add_textbox|`1This item can't be destroyed - smashing it will return it to your backpack if you have room!``|\n";
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wAbout " + itemDef.name + " (" + std::to_string(id) + ")``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_textbox|" + itemDef.description + "|left|\nadd_spacer|small\n" + properties + "\nadd_spacer|small|\nadd_quick_exit|\nend_dialog|iteminfo||Close|"));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
					}
					if (cch.find("action|dialog_return\ndialog_name|sign_edit") == 0) {
						if (world != NULL) {
							if (((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner)) {
								std::stringstream ss(GetTextPointerFromPacket(event.packet));
								std::string to;
								int x = 0;
								int y = 0;
								bool created = false;
								string text = "";
								string world = ((PlayerInfo*)(peer->data))->currentWorld;
								while (std::getline(ss, to, '\n')) {
									string id = to.substr(0, to.find("|"));
									string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
									if (id == "tilex")
									{
										x = atoi(act.c_str());

									}
									else if (id == "tiley")
									{
										y = atoi(act.c_str());
									}
									else if (id == "ch3")
									{
										text = act;
										created = true;
									}
									if (created == true) {
										if (text == "__%&P&%__") {
											sendConsoleMsg(peer, ">> Can't use this!");
											continue;
										}
									}
									if (text.length() < 255) {
										WorldInfo* worldInfo = getPlyersWorld(peer);
										int squaresign = ((PlayerInfo*)(peer->data))->wrenchx + (((PlayerInfo*)(peer->data))->wrenchy * 100);
										updateSignSound(peer, worldInfo->items[squaresign].foreground, squaresign % worldInfo->width, squaresign / worldInfo->width, text, worldInfo->items[squaresign].background);
										worldInfo->items[squaresign].text = text;
									}
								}
							}
						}
					}
					if (cch.find("action|dialog_return") == 0)
					{
						std::stringstream ss(cch);
						std::string to;
						string btn = "";
						bool isRegisterDialog = false;
						bool isFindDialog = false;
						bool Accesspicker = false;
						bool isEditDoorDialog = false;
						bool isEditPDoorDialog = false;
						bool isTrashDialog = false;
						bool isownerdialog = false;
						string trashitemcount = "";
						string dropitemcount = "";
						bool isPwdDoorDialog = false;
						string passwords = "";
						string passwordss = "";
						bool moderator = false;
						bool vip = false;
						bool isOptionalStuffDialog = false;

						bool istradedi1;
						string di1price;
						bool istradery1;
						string ry1price;
						bool istradeac1;
						string ac1price;
						bool istradetk1;
						string tk1price;
						bool istradeln1;
						string ln1price;

						bool isDropDialog = false;

						bool megaphone = false;
						string sbtext = "";

						bool isSecurityDialog = false;
						string c0de = "";

						bool isTradeDialog = false;
						string item = "";

						bool isMailDialog = false;
						string mail = "";

						bool isWarnDialog = false;
						string warntext = "";

						string omgitem = "2";
						int stuffgrav = -1;

						bool isLockDialog = false;
						string pub = "";
						string playerNetId = "";
						string disable_music = "";
						string tempo = "";
						string disable_music_render = "";

						bool isGuildDialog = false;
						string guildName = "";
						string guildStatement = "";
						string guildFlagBg = "";
						string guildFlagFg = "";

						string itemFind = "";
						string username = "";
						string password = "";
						string passwordverify = "";
						string netid = "";
						string email = "";
						string discord = "";
						string stuffitem = "";
						string gravitystr = "";
						string people = "";
						bool spin = 0;
						bool invert = 0;

						string destworld = "", destid = "", label = "", currid = "";
						string strBuyOfferlevel = "";
						bool isLevelBuyDialog = false;

						string strBuyOffergems = "";
						bool isGemsBuyDialog = false;

						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 2) {
								if (infoDat[0] == "buttonClicked") btn = infoDat[1];
								if (infoDat[0] == "dialog_name" && infoDat[1] == "register")
								{
									isRegisterDialog = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "sendwarn")
								{
									isWarnDialog = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "sendsb")
								{
									megaphone = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "trashdialog")
								{
									isTrashDialog = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "dropdialog")
								{
									isDropDialog = true;
								}
								if (isDropDialog) {
									if (infoDat[0] == "dropitemcount") dropitemcount = infoDat[1];

								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "lock_edit") {
									isLockDialog = true;
								} 
								if (infoDat[0] == "dialog_name" && infoDat[1] == "moderator")
								{
									moderator = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "vip")
								{
									vip = true;
								}
								if (infoDat[0] == "allowNoclip" && infoDat[1] == "1")
								{
									if (((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner) || ((PlayerInfo*)(peer->data))->adminLevel > 1336) {

										bool casin = world->isCasino;
										if (world->isCasino == false) {
											world->isCasino = true;
											ENetPeer * currentPeer;
											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer))
												{
													sendConsoleMsg(currentPeer, "World owner has been `4DISABLED `ono clipping in this world`o!");
													if (((PlayerInfo*)(currentPeer->data))->rawName == world->owner || ((PlayerInfo*)(currentPeer->data))->adminLevel > 1119)
													{

													}
													else
													{
														((PlayerInfo*)(currentPeer->data))->isGhost = false;
														sendState(currentPeer);
													}


												}
											}
										}



									}

								}

								if (infoDat[0] == "allowNoclip" && infoDat[1] == "0")
								{
									if (((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner) || ((PlayerInfo*)(peer->data))->adminLevel > 1336) {


										bool casin = std::experimental::filesystem::exists("casino/" + world->name + ".txt");
										if (world->isCasino = true) {
											ENetPeer * currentPeer;
											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer))
												{
													sendConsoleMsg(currentPeer, "World owner has been `2ENABLED `ono clipping in this world`o!");

												}
											}
											world->isCasino = false;

										}

									}
								}
								if (infoDat[0] == "isWorldPublic" && infoDat[1] == "1")
								{
									if (((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner) || ((PlayerInfo*)(peer->data))->adminLevel > 1336) {


										if (getPlyersWorld(peer)->isPublic == false)
										{
											getPlyersWorld(peer)->isPublic = true;
											ENetPeer * currentPeer;
											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer))
												{
													sendConsoleMsg(currentPeer, "World owner has been set the world `2PUBLIC");
												}
											}

										}
									}

								}
								if (infoDat[0] == "isWorldPublic" && infoDat[1] == "0")
								{
									if (((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner) || ((PlayerInfo*)(peer->data))->adminLevel > 1336) {


										if (getPlyersWorld(peer)->isPublic == true)
										{
											getPlyersWorld(peer)->isPublic = false;
											ENetPeer * currentPeer;
											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer))
												{
													sendConsoleMsg(currentPeer, "World owner has been set the world `4PRIVATE");
												}
											}
										}

									}
								}
								if (infoDat[0] == "enablemag" && infoDat[1] == "1")
								{
									if (((PlayerInfo*)(peer->data))->rawName == PlayerDB::getProperName(world->owner) || ((PlayerInfo*)(peer->data))->adminLevel > 1336) {
										getPlyersWorld(peer)->magplant = true;
										PlayerInfo* pinfo = (PlayerInfo*)peer->data;
										ENetPeer * currentPeer;
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{
												sendConsoleMsg(currentPeer, "`oWorld owner has turned `2on `othe magplant!");
											}
										}
									}

								}

								if (infoDat[0] == "enablemag" && infoDat[1] == "0")
								{
									PlayerInfo* pinfo = (PlayerInfo*)peer->data;
									int squaresign = ((PlayerInfo*)(peer->data))->wrenchx + (((PlayerInfo*)(peer->data))->wrenchy * 100);
									getPlyersWorld(peer)->magplant = false;

									ENetPeer * currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer))
										{
											sendConsoleMsg(currentPeer, "`oWorld owner has turned `4off `othe magplant!");
										}
									}
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "guildconfirm") isGuildDialog = true;
								if (isRegisterDialog) {
									if (infoDat[0] == "username") username = infoDat[1];
									if (infoDat[0] == "password") password = infoDat[1];
									if (infoDat[0] == "passwordverify") passwordverify = infoDat[1];
									if (infoDat[0] == "email") email = infoDat[1];
									if (infoDat[0] == "discord") discord = infoDat[1];
								}
								if (isTrashDialog) {
									if (infoDat[0] == "trashitemcount") trashitemcount = infoDat[1];

								}
								if (isGuildDialog) {
									if (infoDat[0] == "gname") guildName = infoDat[1];
									if (infoDat[0] == "gstatement") guildStatement = infoDat[1];
									if (infoDat[0] == "ggcflagbg") guildFlagBg = infoDat[1];
									if (infoDat[0] == "ggcflagfg") guildFlagFg = infoDat[1];
								}
								if (isDropDialog) {
									int x;

									try {
										x = stoi(dropitemcount);
									}
									catch (std::invalid_argument& e) {
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Please enter how many u want to drop"));
										ENetPacket* packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete ps.data;
										continue;
									}
									if (x < 0) {
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] That too less to drop"));
										ENetPacket* packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete ps.data;
										continue;
									}
									if (x > 200) {
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] That too many to drop."));
										ENetPacket* packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete ps.data;
										continue;
									}
									short int currentItemCount = 0;
									for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
									{
										if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == ((PlayerInfo*)(peer->data))->lastdropitem)
										{
											currentItemCount = (unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount;
										}
									}
									if (x <= 0 || x > currentItemCount) {
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oYou cant dupe them."));
										ENetPacket* packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete ps.data;
										continue;
									}
									else {

										int xx = ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1));
										int netid = -1;
										int yy = ((PlayerInfo*)(peer->data))->y;
										DropItem(peer, netid, xx, yy, ((PlayerInfo*)(peer->data))->lastdropitem, x, 0);
										RemoveInventoryItem(((PlayerInfo*)(peer->data))->lastdropitem, x, peer);
										//	DropItem(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y, ((PlayerInfo*)(peer->data))->lastdropitem, x, 0);

									}
								}

								if (isTrashDialog) {
									int x;

									try {
										x = stoi(trashitemcount);
									}
									catch (std::invalid_argument & e) {
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oItem `2Trashed"));
										ENetPacket* packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete ps.data;
										continue;
									}
									short int currentItemCount = 0;
									for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
									{
										if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == ((PlayerInfo*)(peer->data))->lasttrashitem)
										{
											currentItemCount = (unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount;
										}
									}

									if (x <= 0 || x > currentItemCount) {
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oThat too many or too less to `4trash`^!"));
										ENetPacket* packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete ps.data;
										continue;
									}
									if (((PlayerInfo*)(peer->data))->lasttrashitem == 9488 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9490 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9492 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9494 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9496 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9499 || ((PlayerInfo*)(peer->data))->lasttrashitem == 18 || ((PlayerInfo*)(peer->data))->lasttrashitem == 32) {
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oYou can't trash this item!"));
										ENetPacket* packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete ps.data;
										continue;

									}
									else {
										//	sendDrop(peer, -1, ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1)), ((PlayerInfo*)(peer->data))->y, ((PlayerInfo*)(peer->data))->lastdropitem, x, 0);
										RemoveInventoryItem(((PlayerInfo*)(peer->data))->lasttrashitem, x, peer);
										sendSound(peer, "trash.wav");
									}
								}
								if (isWarnDialog) {
									if (infoDat[0] == "warntext")
									{
										warntext = infoDat[1];
										ENetPeer* currentPeerpx;

										for (currentPeerpx = server->peers;
											currentPeerpx < &server->peers[server->peerCount];
											++currentPeerpx)
										{
											if (currentPeerpx->state != ENET_PEER_STATE_CONNECTED)
												continue;

											if (isHere(peer, currentPeerpx))
											{




												if (((PlayerInfo*)(currentPeerpx->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) // if last wrench
												{
													GamePacket ps2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`0Warning from `4ADMIN`0: " + warntext), "audio/hub_open.wav"), 0));
													ENetPacket* packet2 = enet_packet_create(ps2.data,
														ps2.len,
														ENET_PACKET_FLAG_RELIABLE);
													enet_peer_send(currentPeerpx, 0, packet2);
													GamePacket pto = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Applied punishment on " + ((PlayerInfo*)(peer->data))->lastInfoname + "."));
													//memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
													ENetPacket* packetto = enet_packet_create(pto.data,
														pto.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(peer, 0, packetto);
												}
											}
										}
										GamePacket p6 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `w[`cMOD LOGS `w- " + currentDateTime() + "`w] `2" + ((PlayerInfo*)(peer->data))->displayName + " (`$" + ((PlayerInfo*)(peer->data))->tankIDName + "`2) has `4warned `2" + ((PlayerInfo*)(peer->data))->lastInfoname));
										string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
										BYTE* data = new BYTE[5 + text.length()];
										BYTE zero = 0;
										int type = 3;
										memcpy(data, &type, 4);
										memcpy(data + 4, text.c_str(), text.length());
										memcpy(data + 4 + text.length(), &zero, 1);
										ENetPeer* currentPeer;
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (!((PlayerInfo*)(currentPeer->data))->radio)
												continue;
											if (((PlayerInfo*)(currentPeer->data))->adminLevel > 333) {
												ENetPacket* packet6 = enet_packet_create(p6.data,
													p6.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet6);




												ENetPacket* packet2 = enet_packet_create(data,
													5 + text.length(),
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet2);

												//enet_host_flush(server);
											}
										}
									}
								}
								if (megaphone) {
									if (infoDat[0] == "sbtext")
									{
										sbtext = infoDat[1];
										GamePacket p;


										p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:0_PL:4_OID:_CT:[SB]_ `w** `5Super-Broadcast`w from `2" + (((PlayerInfo*)(peer->data))->rawName + "`w (in `$" + ((PlayerInfo*)(peer->data))->currentWorld + "`w) ** :`# " + sbtext)));


										sendConsoleMsg(peer, "`o >>`5 Super-Broadcast `osent. `oUsed `$1 Megaphone.");
										string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
										BYTE* data = new BYTE[5 + text.length()];
										BYTE zero = 0;
										int type = 3;
										memcpy(data, &type, 4);
										memcpy(data + 4, text.c_str(), text.length());
										memcpy(data + 4 + text.length(), &zero, 1);
										ENetPeer* currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (!((PlayerInfo*)(currentPeer->data))->radio)
												continue;

											ENetPacket* packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packet);




											ENetPacket* packet2 = enet_packet_create(data,
												5 + text.length(),
												ENET_PACKET_FLAG_RELIABLE);


											enet_peer_send(currentPeer, 0, packet2);

											//enet_host_flush(server);
										}
										delete data;
										delete p.data;
									}
								}

								if (vip) {
									((PlayerInfo*)(peer->data))->wls = ((PlayerInfo*)(peer->data))->wls - 200;
									GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "You received `cVIP"), "audio/hub_open.wav"), 0));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
									std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");




									if (ifff.fail()) {
										ifff.close();


									}
									if (ifff.is_open()) {
									}
									json j;
									ifff >> j; //load

									j["adminLevel"] = 111;

									//j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;


									std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
									if (!o.is_open()) {
										cout << GetLastError() << endl;
										_getch();
									}

									o << j << std::endl;
									enet_peer_disconnect_later(peer, 0);
								}
								if (moderator) {
									((PlayerInfo*)(peer->data))->wls = ((PlayerInfo*)(peer->data))->wls - 500;
									GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`2You Purchased `#MODERATOR"), "audio/hub_open.wav"), 0));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
									std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");



									if (ifff.fail()) {
										ifff.close();


									}
									if (ifff.is_open()) {
									}
									json j;
									ifff >> j; //load

									j["adminLevel"] = 444;

									//j["friends"] = ((PlayerInfo*)(peer->data))->friendinfo;


									std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
									if (!o.is_open()) {
										cout << GetLastError() << endl;
										_getch();
									}

									o << j << std::endl;
									enet_peer_disconnect_later(peer, 0);
								}
								if (isOptionalStuffDialog) {
									if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {
										int stuffitemi = -1;
										int gravity = 100;

										int x = ((PlayerInfo*)(peer->data))->lastPunchX;
										int y = ((PlayerInfo*)(peer->data))->lastPunchY;

										if (infoDat[0] == "stuffitem") stuffitem = infoDat[1];


										if (infoDat[0] == "gravity") gravitystr = infoDat[1];

										if (has_only_digits(stuffitem)) stuffitemi = atoi(stuffitem.c_str());
										if (has_only_digits_wnegative(gravitystr)) gravity = atoi(gravitystr.c_str());

										if (gravity > -1000 && gravity < 1000 && stuffitemi > -1 && stuffitemi < 9142) {
											world->stuffID = stuffitemi;
											world->gravity = gravity;
										}

										updateStuffWeather(peer, x, y, stuffitemi, world->items[x + (y * world->width)].background, gravity, invert, spin);
										getPlyersWorld(peer)->weather = 29;
									}

								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "editdoor")
								{
									isEditDoorDialog = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "editpdoor")
								{
									isEditPDoorDialog = true;
								}
								if (isEditDoorDialog || isEditPDoorDialog) {
									if (infoDat[0] == "dest")
									{
										string a = getStrUpper(infoDat[1]);
										vector<string> b = explode(":", a);
										if (b.size() == 1)
										{
											destworld = b[0];
										}
										else if (b.size() > 1)
										{
											destworld = b[0];
											destid = b[1];
										}
									}
									if (infoDat[0] == "label")
									{
										label = infoDat[1];
									}
									if (infoDat[0] == "doorid")
									{
										currid = getStrUpper(infoDat[1]);
									}
									if (infoDat[0] == "doorpw")
									{
										passwordss = getStrUpper(infoDat[1]);
									}
								}
								if (isEditDoorDialog || isEditPDoorDialog)
								{
									PlayerInfo* pinfo = (PlayerInfo*)peer->data;
									if (pinfo->wrenchsession < 0 && pinfo->wrenchsession > 6000) break;
									world->items[pinfo->wrenchsession].destWorld = destworld;
									world->items[pinfo->wrenchsession].destId = destid;
									world->items[pinfo->wrenchsession].currId = currid;
									world->items[pinfo->wrenchsession].label = label;
									world->items[pinfo->wrenchsession].password = passwordss;
									string labelForDoor = label == "" ? (destid == "" ? destworld : destworld + "...") : label;
									updateDoor(peer, world->items[pinfo->wrenchsession].foreground, pinfo->wrenchsession % world->width, pinfo->wrenchsession / world->width, labelForDoor);
									// .....
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "pwddoor")
								{
									isPwdDoorDialog = true;
								}
								if (isPwdDoorDialog) {
									if (infoDat[0] == "doorpass") passwords = infoDat[1];
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "findid")
								{
									isFindDialog = true;
								}
								if (isFindDialog) {
									if (infoDat[0] == "item") itemFind = infoDat[1];
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "omgc0de") isSecurityDialog = true;
								if (isSecurityDialog) {
									if (infoDat[0] == "item") c0de = infoDat[1];
								}
								if (infoDat[0] == "netid") {
									netid = infoDat[1];
									Accesspicker = true;
								}
							}
						}
						if (btn == "worldPublic") if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = true;
						if (btn == "worldPrivate") if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner) getPlyersWorld(peer)->isPublic = false;
						if (btn == "backsocialportal") {
							if (((PlayerInfo*)(peer->data))->joinguild == true) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|showguild|Show Guild Members``|0|0|\nadd_button|guildrewards|Guild Rewards``|0|0|\nend_dialog||OK||\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|createguildinfo|Create Guild``|0|0|\nend_dialog||OK||\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "traderubble") {
							if (((PlayerInfo*)(peer->data))->ban > 0) {
								int valgem = rand() % 15;
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + valgem;
								((PlayerInfo*)(peer->data))->ban = ((PlayerInfo*)(peer->data))->ban - 1;
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You got " + to_string(valgem) + " gems."));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
								GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packetpp = enet_packet_create(pp.data,
									pp.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetpp);
								delete pp.data;
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`3You don't have any rubbles"));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}
							if (((PlayerInfo*)(peer->data))->haveGrowId) {
								savejson(peer);
							}
						}
						if (btn == "claim") {
							bool success = true;
							SaveShopsItemMoreTimes(7484, 1, peer, success);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|`wDaily login``|left|18|\nadd_label|small|`oYou received 1 `1Winter chest!|left|18|\n\nadd_spacer|\nend_dialog|okk|`2Thanks|No|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}

						if (btn == "openwinter") {
#pragma warning(disable: 4996)
							RemoveInventoryItem(7484, 1, peer);
							int kuriPrizaDuot = rand() % 2; 
							int gemChance = rand() % 5000;
							GiveChestPrizeGems(peer, gemChance);
							time_t currentTime;
							struct tm *localTime;
							char buffer[80];

							time(&currentTime); // Get the current time
							localTime = localtime(&currentTime); // Convert the current time to the local time

							int yer = localTime->tm_year + 1900;
							int Mon = localTime->tm_mon + 1;
							int Day = localTime->tm_mday;
							int Hour = localTime->tm_hour;
							int Min = localTime->tm_min;
							int Sec = localTime->tm_sec;
							int IncDay = Day + 1;
							if (IncDay >= 7) {
								int res = IncDay / 7;
								int newDay = IncDay % 7;
								Day += res;
								if (Day > 7) {
									Day = 1;
								}
							}
							string usedban = ((PlayerInfo*)(peer->data))->rawName;

							std::fstream gay("event.txt", std::ios::in | std::ios::out | std::ios::ate);
							gay << usedban + "|" << IncDay << "/" << Mon << "/" << yer << endl;
							gay.close();
						}
						if (btn == "giveownership") {
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{

									if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) {
										GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|`wGiving ownership to people``|left|18|\nadd_label|small|`oAre you sure you want to give the ownership to this player?``|left|18|\n\nadd_spacer|\nend_dialog|giveowner|`2Yes|No|\nadd_quick_exit|"));
										ENetPacket * packet2 = enet_packet_create(p2.data,
											p2.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packet2);
										delete p2.data;
									}
								}
							}
						}
						if (btn == "rankinfo") {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|`wRank info``|left|18|\nadd_label|big|`2Newbie (< 10)|left|18|\n\nadd_spacer|small|\nadd_textbox|`wNothing for now|left|\nadd_spacer|small|\nadd_label|big|`1Advance (> 10)|left|\nadd_spacer|small|\nadd_textbox|`2Extra `wgems when breaking blocks!|left|\nadd_spacer|small|\nadd_label|big|`cPro (>= 50)|left|\nadd_spacer|small|\nadd_textbox|`2Extra `wgems when breaking blocks (3x)|left|\nadd_spacer|small|\nadd_label|big|`eMaster (>= 100)|left|\nadd_spacer|small|\nadd_textbox|`2Extra `wgems when breaking blocks (4x)|left|\nadd_spacer|small|\nadd_label|big|`9Expert (>= 150)|left|\nadd_spacer|small|\nadd_textbox|`2Extra `wgems when breaking blocks (5x)|left|\nadd_spacer|small|\nadd_label|big|`5A`4C`9E|left|\nadd_spacer|small|\nadd_textbox|`2Extra `wgems when breaking blocks (6x) + /ace (ace sb)|left|\n\nadd_spacer|\nend_dialog|okk|`2Thanks|No|\nadd_quick_exit|"));
							ENetPacket * packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "trades") {
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{

									if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) {
										GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|`oTrade!``|left|18|\nadd_label|small|`oChoose the items that u want to sell.``|left|18|\n\nadd_spacer|small|\nadd_button_with_icon|di1||staticBlueFrame|2952||\nadd_button_with_icon|ry1||staticBlueFrame|5480||\nadd_button_with_icon|tk1||staticBlueFrame|5078||\nadd_button_with_icon|wr1||staticBlueFrame|7912||\nadd_button_with_icon|pw1||staticBlueFrame|6312||\nend_dialog||OK||\nadd_quick_exit|"));
										ENetPacket * packet2 = enet_packet_create(p2.data,
											p2.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packet2);
										delete p2.data;
									}
								}
							}
						}
						if (btn == "legendbot") {

							((PlayerInfo*)(peer->data))->cloth_shirt = 1780;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have legendary bot now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9Quest step complete!!"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);


							delete p2.data;
							delete p.data;
							int effect = 90;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {

									int x = ((PlayerInfo*)(peer->data))->x;
									int y = ((PlayerInfo*)(peer->data))->y;
									GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

									ENetPacket* packetd = enet_packet_create(psp.data,
										psp.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetd);

									delete psp.data;
									bool dary = std::experimental::filesystem::exists("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
									if (dary == false)
									{
										int effect = 48;
										int x = ((PlayerInfo*)(currentPeer->data))->x;
										int y = ((PlayerInfo*)(currentPeer->data))->y;
										GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

										ENetPacket* packetd = enet_packet_create(psp.data,
											psp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packetd);
										GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->displayName + " `5earned the achievement ''DARY!''!"));
										ENetPacket* packet3 = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet3);
										delete p3.data;

										ofstream myfile;
										myfile.open("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
										myfile << "true";
										myfile.close();
									}
								}
							}

						}
						if (btn == "storeinvupgrade")
						{
							short nextSpace = 0;

							if (((PlayerInfo*)(peer->data))->currentInventorySize + 30 > 200)
							{
								nextSpace = 200;
							}
							else
							{
								nextSpace = ((PlayerInfo*)(peer->data))->currentInventorySize + 30;
							}

							if (((PlayerInfo*)(peer->data))->currentInventorySize == 200)
							{
								sendConsoleMsg(peer, "You already reached the max backpack level!");
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`2Purchase `8Inventory Upgrade`2!``|left|6204|\nadd_spacer|small|\nadd_label|small|\nadd_textbox|`wNOTE : This inventory upgrade will cost (`21000 Gems`w)``|\nadd_textbox|`oYour inventory space is`8 " + to_string(((PlayerInfo*)(peer->data))->currentInventorySize) + " `onow.|\nadd_label|small|\nadd_textbox|`9After purchasing an inventory upgrade, your inventory will have`2 " + to_string(nextSpace) + "`9 spaces.|left|8|\nadd_spacer|small|\nadd_button|buyinvupgrade|`wUpgrade my inventory!|0|0|\nadd_spacer|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}

						if (btn == "buyinvupgrade") {
							if (((PlayerInfo*)(peer->data))->gem > 1000) {
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 1000;
								savejson(peer);
								bool success = true;


								short nextSpace = 0;

								if (((PlayerInfo*)(peer->data))->currentInventorySize + 30 > 200)
								{
									nextSpace = 200;
								}
								else
								{
									nextSpace = ((PlayerInfo*)(peer->data))->currentInventorySize + 30;
								}

								ofstream fs("usersinventorysize/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								fs << nextSpace;
								fs.close();
								sendConsoleMsg(peer, "`2Payment Succesful! `2Successfully upgraded your inventory!");
								GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5 = enet_packet_create(p5.data,
									p5.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								delete p5.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wNot Purchased|left|5016|\nadd_spacer|small|\nadd_textbox|`oPayment `4declined!|small|left|\nadd_button|cl0se|`oClose|\n"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}



						if (btn == "legendname") {

							string name2 = ((PlayerInfo*)(peer->data))->displayName = ((PlayerInfo*)(peer->data))->tankIDName + " of Legend";
							GamePacket p7 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), name2));
							memcpy(p7.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor

							((PlayerInfo*)(peer->data))->displayName = name2;
							ENetPacket* packet7 = enet_packet_create(p7.data,
								p7.len,
								ENET_PACKET_FLAG_RELIABLE);


							delete p7.data;

							int xx = ((PlayerInfo*)(peer->data))->x;
							int yy = ((PlayerInfo*)(peer->data))->y;
							string act = ((PlayerInfo*)(peer->data))->currentWorld;
							joinWorld(peer, act, xx, yy);


							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have legendary name now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9Quest step complete!!"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);


							delete p2.data;
							delete p.data;
							int effect = 90;
							((PlayerInfo*)(peer->data))->legend == true;
							savejson(peer);
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {
									string act = ((PlayerInfo*)(peer->data))->currentWorld;
									enet_peer_send(currentPeer, 0, packet7);
									//WorldInfo info = worldDB.get(act);
									// sendWorld(currentPeer, &info);
									int x = 32;
									int y = 32;

									//	sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
									//		 joinWorld(currentPeer, act, 0, 0);

									bool dary = std::experimental::filesystem::exists("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
									if (dary == false)
									{
										int effect = 48;
										int x = ((PlayerInfo*)(currentPeer->data))->x;
										int y = ((PlayerInfo*)(currentPeer->data))->y;
										GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

										ENetPacket* packetd = enet_packet_create(psp.data,
											psp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packetd);
										GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->displayName + " `5earned the achievement ''DARY!''!"));
										ENetPacket* packet3 = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet3);
										delete p3.data;

										ofstream myfile;
										myfile.open("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
										myfile << "true";
										myfile.close();
									}
								}

							}
						}


						if (btn == "legendwing") {

							((PlayerInfo*)(peer->data))->cloth_back = 1784;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have legendary wing now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9Quest step complete!!"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							delete p.data;
							int effect = 90;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {



									bool dary = std::experimental::filesystem::exists("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
									if (dary == false)
									{
										int effect = 48;
										int x = ((PlayerInfo*)(currentPeer->data))->x;
										int y = ((PlayerInfo*)(currentPeer->data))->y;
										GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

										ENetPacket* packetd = enet_packet_create(psp.data,
											psp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packetd);
										GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->displayName + " `5earned the achievement ''DARY!''!"));
										ENetPacket* packet3 = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet3);
										delete p3.data;

										ofstream myfile;
										myfile.open("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
										myfile << "true";
										myfile.close();
									}
								}

							}
						}

						if (btn == "legendsky") {

							((PlayerInfo*)(peer->data))->cloth_back = 7734;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have Legendary Dragon Knight's Wings!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9Quest step complete!!"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							delete p.data;

							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {


									bool dary = std::experimental::filesystem::exists("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
									if (dary == false)
									{
										int effect = 48;
										int x = ((PlayerInfo*)(currentPeer->data))->x;
										int y = ((PlayerInfo*)(currentPeer->data))->y;
										GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

										ENetPacket* packetd = enet_packet_create(psp.data,
											psp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packetd);
										GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->displayName + " `5earned the achievement ''DARY!''!"));
										ENetPacket* packet3 = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet3);
										delete p3.data;

										ofstream myfile;
										myfile.open("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
										myfile << "true";
										myfile.close();
									}

								}
							}
						}
						if (btn == "enablemag") {
							int squaresign = ((PlayerInfo*)(peer->data))->wrenchx + (((PlayerInfo*)(peer->data))->wrenchy * 100);
							getPlyersWorld(peer)->magplant = true;
							sendMag(peer, squaresign % getPlyersWorld(peer)->width, squaresign / getPlyersWorld(peer)->width, 112, 1, true, true);
							PlayerInfo* pinfo = (PlayerInfo*)peer->data;
							ENetPeer * currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									sendConsoleMsg(currentPeer, "`oWorld owner has turned `2on `othe magplant!");
								}
							}
						}
						if (btn == "disablemag") {
							int squaresign = ((PlayerInfo*)(peer->data))->wrenchx + (((PlayerInfo*)(peer->data))->wrenchy * 100);
							getPlyersWorld(peer)->magplant = false;
							sendMag(peer, squaresign % getPlyersWorld(peer)->width, squaresign / getPlyersWorld(peer)->width, 112, 1, false, false);
							PlayerInfo* pinfo = (PlayerInfo*)peer->data;
							ENetPeer * currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									sendConsoleMsg(currentPeer, "`oWorld owner has turned `2on `othe magplant!");
								}
							}
						}
						if (btn == "takegems")
						{
							PlayerInfo* pinfo = (PlayerInfo*)peer->data;

							int netID = pinfo->netID;
							pinfo->gem = pinfo->gem + world->maggems;
							world->maggems = 0;
							Player::OnSetBux(peer, pinfo->gem, 0);

						}



						if (btn == "legendkatana") {
							((PlayerInfo*)(peer->data))->cloth_hand = 2592;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have legendary katana now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9Quest step complete!!"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							delete p.data;

							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {





									bool dary = std::experimental::filesystem::exists("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
									if (dary == false)
									{
										int effect = 48;
										int x = ((PlayerInfo*)(currentPeer->data))->x;
										int y = ((PlayerInfo*)(currentPeer->data))->y;
										GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

										ENetPacket* packetd = enet_packet_create(psp.data,
											psp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packetd);
										GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->displayName + " `5earned the achievement ''DARY!''!"));
										ENetPacket* packet3 = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet3);
										delete p3.data;

										ofstream myfile;
										myfile.open("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
										myfile << "true";
										myfile.close();
									}
								}

							}
						}

						if (btn == "legenddragon") {

							((PlayerInfo*)(peer->data))->cloth_hand = 1782;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have legendary dragon now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9Quest step complete!!"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							delete p.data;

							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {


									bool dary = std::experimental::filesystem::exists("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
									if (dary == false)
									{
										int effect = 48;
										int x = ((PlayerInfo*)(currentPeer->data))->x;
										int y = ((PlayerInfo*)(currentPeer->data))->y;
										GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

										ENetPacket* packetd = enet_packet_create(psp.data,
											psp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packetd);
										GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->displayName + " `5earned the achievement ''DARY!''!"));
										ENetPacket* packet3 = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet3);
										delete p3.data;

										ofstream myfile;
										myfile.open("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
										myfile << "true";
										myfile.close();
									}
								}
							}

						}

						if (btn == "legendwhip") {


							((PlayerInfo*)(peer->data))->cloth_hand = 6026;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have whip of truth now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`9Quest step complete!!"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							delete p.data;

							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {


									bool dary = std::experimental::filesystem::exists("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
									if (dary == false)
									{
										int effect = 48;
										int x = ((PlayerInfo*)(currentPeer->data))->x;
										int y = ((PlayerInfo*)(currentPeer->data))->y;
										GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));

										ENetPacket* packetd = enet_packet_create(psp.data,
											psp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packetd);
										GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ((PlayerInfo*)(peer->data))->displayName + " `5earned the achievement ''DARY!''!"));
										ENetPacket* packet3 = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet3);
										delete p3.data;

										ofstream myfile;
										myfile.open("achievements/dary/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
										myfile << "true";
										myfile.close();
									}
								}
							}

						}


						if (btn == "ringforce") {
							((PlayerInfo*)(peer->data))->cloth_hand = 1874;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have Ring Of Force now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;

						}
						if (btn == "ringwinds") {
							((PlayerInfo*)(peer->data))->cloth_hand = 1876;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have Ring Of Winds now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringone") {
							((PlayerInfo*)(peer->data))->cloth_hand = 1904;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have The One Ring now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringwisdom") {
							((PlayerInfo*)(peer->data))->cloth_hand = 1996;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have Ring of Wisdom now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringwater") {
							((PlayerInfo*)(peer->data))->cloth_hand = 2970;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have Ring Of Water now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringsaving") {
							((PlayerInfo*)(peer->data))->cloth_hand = 3140;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have Ring Of Savings now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringsmithing") {
							((PlayerInfo*)(peer->data))->cloth_hand = 3174;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have Ring Of Smithing now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringshrinking") {
							((PlayerInfo*)(peer->data))->cloth_hand = 6028;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have Ring Of Shrinking now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ringnature") {
							((PlayerInfo*)(peer->data))->cloth_hand = 6846;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have Ring of Nature now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "geminiring") {
							((PlayerInfo*)(peer->data))->cloth_hand = 1986;
							sendState(peer);

							((PlayerInfo*)(peer->data))->skinColor = 0x8295C3FF;
							sendClothes(peer);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You have Gemini Ring now!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "wban")
						{
							if (((PlayerInfo*)(peer->data))->haveGrowId && ((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner || ((PlayerInfo*)(peer->data))->adminLevel > 333)
							{
								ENetPeer* currentPeerp;

								for (currentPeerp = server->peers;
									currentPeerp < &server->peers[server->peerCount];
									++currentPeerp)
								{
									if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
										continue;



									string name = ((PlayerInfo*)(peer->data))->displayName;
									string kickname = ((PlayerInfo*)(peer->data))->lastInfoname;
									//string kickname = ((PlayerInfo*)(peer->data))->displayName;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `o" + name + " `4world bans " + "`o" + kickname + " from `w" + world->name + "`o!"));
									string text = "action|play_sfx\nfile|audio/repair.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);

									if (isHere(peer, currentPeerp))
									{
										if (((PlayerInfo*)(currentPeerp->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) // if last wrench
										{
											if (((PlayerInfo*)(peer->data))->adminLevel < 999) {
												if (((PlayerInfo*)(currentPeerp->data))->adminLevel > 333 && ((PlayerInfo*)(currentPeerp->data))->isNicked == false) {
													GamePacket p7 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You can't ban an Moderator/Owner"));
													ENetPacket* packet7 = enet_packet_create(p7.data,
														p7.len,
														ENET_PACKET_FLAG_RELIABLE);
													enet_peer_send(peer, 0, packet7);
													delete p7.data;
													break;
												}
												else {
													namespace fs = std::experimental::filesystem;

													if (!fs::is_directory("worldbans/" + getPlyersWorld(peer)->name) || !fs::exists("worldbans/" + getPlyersWorld(peer)->name)) {
														fs::create_directory("worldbans/" + getPlyersWorld(peer)->name);

														std::ofstream outfile("worldbans/" + getPlyersWorld(peer)->name + "/" + ((PlayerInfo*)(currentPeerp->data))->rawName);

														outfile << "worldbanned by: " + ((PlayerInfo*)(peer->data))->rawName;

														outfile.close();
													}
													else
													{
														std::ofstream outfile("worldbans/" + getPlyersWorld(peer)->name + "/" + ((PlayerInfo*)(currentPeerp->data))->rawName);

														outfile << "worldbanned by: " + ((PlayerInfo*)(peer->data))->rawName;

														outfile.close();
													}

													sendPlayerLeave(currentPeerp, (PlayerInfo*)(currentPeerp->data));
													sendWorldOffers(currentPeerp);


													((PlayerInfo*)(currentPeerp->data))->currentWorld = "EXIT";

												}
											}
											else {
												namespace fs = std::experimental::filesystem;

												if (!fs::is_directory("worldbans/" + getPlyersWorld(peer)->name) || !fs::exists("worldbans/" + getPlyersWorld(peer)->name)) {
													fs::create_directory("worldbans/" + getPlyersWorld(peer)->name);

													std::ofstream outfile("worldbans/" + getPlyersWorld(peer)->name + "/" + ((PlayerInfo*)(currentPeerp->data))->rawName);

													outfile << "worldbanned by: " + ((PlayerInfo*)(peer->data))->rawName;

													outfile.close();
												}
												else
												{
													std::ofstream outfile("worldbans/" + getPlyersWorld(peer)->name + "/" + ((PlayerInfo*)(currentPeerp->data))->rawName);

													outfile << "worldbanned by: " + ((PlayerInfo*)(peer->data))->rawName;

													outfile.close();
												}

												sendPlayerLeave(currentPeerp, (PlayerInfo*)(currentPeerp->data));
												sendWorldOffers(currentPeerp);


												((PlayerInfo*)(currentPeerp->data))->currentWorld = "EXIT";
											}
										}
										ENetPacket* packetsou = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);



										enet_peer_send(currentPeerp, 0, packetsou);
										enet_peer_send(currentPeerp, 0, packet);
										delete data;
										delete p.data;

									}

								}
							}
						}
						if (btn == "autoban")
						{
							// Warning from `4System``: You've been `4BANNED`` from `wGrowtopia`` for 60 days``


						}
						if (btn == "kick")
						{
							if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner || ((PlayerInfo*)(peer->data))->adminLevel > 333)
							{
								ENetPeer * currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;



									string name = ((PlayerInfo*)(peer->data))->displayName;
									string kickname = ((PlayerInfo*)(peer->data))->lastInfoname;
									//string kickname = ((PlayerInfo*)(peer->data))->displayName;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), name + " `4kicks " + "`w" + kickname));
									string text = "action|play_sfx\nfile|audio/male_scream.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);

									if (isHere(peer, currentPeer))
									{
										ENetPacket * packetsou = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);


										enet_peer_send(currentPeer, 0, packetsou);
										enet_peer_send(currentPeer, 0, packet);


										int x = 3040;
										int y = 736;


										for (int i = 0; i < world->width*world->height; i++)
										{
											if (world->items[i].foreground == 6) {
												x = (i%world->width) * 32;
												y = (i / world->width) * 32;
											}
										}
										GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x, y));
										memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
										ENetPacket * packet2 = enet_packet_create(p2.data,
											p2.len,
											ENET_PACKET_FLAG_RELIABLE);

										if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo)
										{
											enet_peer_send(currentPeer, 0, packet2);
										}



										delete p2.data;
										delete p.data;
										delete data;

									}

								}
							}
						}

						if (btn == "pull")
						{
							if (((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner || ((PlayerInfo*)(peer->data))->adminLevel > 333)
							{
								ENetPeer * currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									string name = ((PlayerInfo*)(currentPeer->data))->rawName;
									int pullX = ((PlayerInfo*)(peer->data))->x;
									int pullY = ((PlayerInfo*)(peer->data))->y;


									if (name == ((PlayerInfo*)(peer->data))->lastInfo)
									{
										if (isHere(peer, currentPeer) && getPlyersWorld(peer)->name != "EXIT")
										{
											string name = ((PlayerInfo*)(peer->data))->displayName;
											string pullname = ((PlayerInfo*)(currentPeer->data))->displayName;
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), name + " `5pulls " + "`w" + pullname));
											string text = "action|play_sfx\nfile|audio/object_spawn.wav\ndelayMS|0\n";
											BYTE* data = new BYTE[5 + text.length()];
											BYTE zero = 0;
											int type = 3;
											memcpy(data, &type, 4);
											memcpy(data + 4, text.c_str(), text.length());
											memcpy(data + 4 + text.length(), &zero, 1);

											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packet);
											enet_peer_send(peer, 0, packet);




											ENetPacket * packetsou = enet_packet_create(data,
												5 + text.length(),
												ENET_PACKET_FLAG_RELIABLE);


											enet_peer_send(currentPeer, 0, packetsou);
											enet_peer_send(peer, 0, packetsou);

											GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), pullX, pullY));
											memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
											ENetPacket * packet2 = enet_packet_create(p2.data,
												p2.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packet2);

											GamePacket pto = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You have been pulled by " + ((PlayerInfo*)(peer->data))->displayName));
											//memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
											ENetPacket * packetto = enet_packet_create(pto.data,
												pto.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeer, 0, packetto);

											delete pto.data;
											delete p2.data;
											delete p.data;

										}
									}
								}
							}






						}
						if (btn == "clearworld") {
							if (((PlayerInfo*)(peer->data))->gem > 5000) {
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 5000;
								savejson(peer);
								GamePacket p5x = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5x = enet_packet_create(p5x.data,
									p5x.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5x);
								delete p5x.data;
								int x = 0;
								int y = 0;
								if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT") {
									TileExtra data;
									data.packetType = 0x5;
									data.characterState = 8;
									data.charStat = 8;
									data.blockid = 0;
									data.backgroundid = 0;
									data.visual = 0x00010000;

									for (int i = 0; i < world->width * world->height; i++)
									{
										if (world->items[i].foreground != 6 && world->items[i].foreground != 8 && getItemDef(world->items[i].foreground).blockType != BlockTypes::LOCK) {


											world->items[i].foreground = 0;
											world->items[i].background = 0;
											x = (i % world->width);
											y = (i / world->width);
											data.punchX = x;
											data.punchY = y;
											ENetPeer * currentPeer;
											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer))
												{
													SendPacketRaw2(192, packBlockVisual222(&data), 100, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
												}
											}
										}
									}

									Player::OnConsoleMessage(peer, "`oUsed `4Growtale's `2Fast-Realtime-Clear system`w (like real gt)!``");
								}
							}
							else {
								Player::OnConsoleMessage(peer, "`oYou don't have enough gem to clear worlds!``");
							}
						}
						int x = ((PlayerMoving*)(peer->data))->punchX;
						int y = ((PlayerMoving*)(peer->data))->punchY;
						int causedBy = ((PlayerMoving*)(peer->data))->netID;
						int tile = ((PlayerMoving*)(peer->data))->plantingTree;
						if (btn == "joinguildzzz") {
							((PlayerInfo*)(peer->data))->guild = ((PlayerInfo*)(peer->data))->guildlast;
							((PlayerInfo*)(peer->data))->isinvited = false;
							((PlayerInfo*)(peer->data))->joinguild = true;

							string fixedguildName = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild);

							/*
							std::ifstream ifs2("guilds/" + fixedguildName + ".json");
							if (ifs2.fail()) {
								ifs2.close();
							}
							if (ifs2.is_open()) {

							}
							json j2;
							ifs2 >> j2;*/

							guildmem.push_back(((PlayerInfo*)(peer->data))->rawName);

						}

						if (btn == "inviteguildbutton") {
							if (((PlayerInfo*)(peer->data))->guild != "") {
								int number = ((PlayerInfo*)(peer->data))->guildmatelist.size();
								if (number > 9) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `3GUILD ERROR: `oYou already have `450 `oGuild members! Please remove some before adding new ones!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
									continue;
								}
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{
										if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) {
											string name = ((PlayerInfo*)(currentPeer->data))->rawName;
											if (((PlayerInfo*)(currentPeer->data))->guild != "") {
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `3GUILD ERROR: `w" + ((PlayerInfo*)(currentPeer->data))->displayName + "`o is already in a Guild!"));
												ENetPacket* packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(peer, 0, packet);
												delete p.data;
											}
											else {
												GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`5[`wGuild request sent to `2" + ((PlayerInfo*)(currentPeer->data))->displayName + "`5]"));
												ENetPacket* packet4 = enet_packet_create(p4.data,
													p4.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(peer, 0, packet4);
												delete p4.data;
												string text = "action|play_sfx\nfile|audio/tip_start.wav\ndelayMS|0\n";
												BYTE* data = new BYTE[5 + text.length()];
												BYTE zero = 0;
												int type = 3;
												memcpy(data, &type, 4);
												memcpy(data + 4, text.c_str(), text.length());
												memcpy(data + 4 + text.length(), &zero, 1);
												ENetPacket* packet2 = enet_packet_create(data,
													5 + text.length(),
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet2);
												delete data;
												((PlayerInfo*)(currentPeer->data))->guildlast = ((PlayerInfo*)(peer->data))->guild;
												((PlayerInfo*)(currentPeer->data))->isinvited = true;
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5[GUILD REQUEST] `oYou've been invited to join `2" + ((PlayerInfo*)(peer->data))->guild + "`o by `w" + ((PlayerInfo*)(peer->data))->displayName + "`o! To accept, `wwrench yourself `oand then choose `2Join " + ((PlayerInfo*)(peer->data))->guild + "`o."));
												ENetPacket* packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet);
												delete p.data;
											}
										}
									}
								}
							}
							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5[GUILD ERROR] `oYou must be in a Guild as a Elder or higher in order to invite players!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "joinguild") {
							vector<string> gmembers;
							string guildname = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guildlast);
							if (guildname != "") {
								std::ifstream ifff("guilds/" + guildname + ".json");
								if (ifff.fail()) {
									ifff.close();
									cout << "[!] Failed loading guilds/" + guildname + ".json! From " + ((PlayerInfo*)(peer->data))->displayName + "." << endl;
								}
								json j;
								ifff >> j;

								for (int i = 0; i < j["Member"].size(); i++) {
									gmembers.push_back(j["Member"][i]);
								}

								ifff.close();

								int membercount = gmembers.size();

								if (membercount > 14) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5[GUILD ALERT] `oThat guild is already full!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
								else {
									((PlayerInfo*)(peer->data))->guild = ((PlayerInfo*)(peer->data))->guildlast;
									((PlayerInfo*)(peer->data))->guildlast = "";
									((PlayerInfo*)(peer->data))->isinvited = false;
									((PlayerInfo*)(peer->data))->joinguild = true;
									updateInvis(peer);

									std::ifstream iffff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
									if (iffff.fail()) {
										iffff.close();
										continue;
									}
									if (iffff.is_open()) {
									}
									json x;
									iffff >> x; //load


									x["guild"] = ((PlayerInfo*)(peer->data))->guild; //edit
									x["joinguild"] = ((PlayerInfo*)(peer->data))->joinguild;

									std::ofstream ox("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
									if (!ox.is_open()) {
										cout << GetLastError() << endl;
										_getch();
									}
									ox << x << std::endl;
									std::ifstream ifff("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json");
									if (ifff.fail()) {
										ifff.close();
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Error: `oGuild does not exist! If you are seeing this message, please take a screenshot and send it to a developer!"));
										ENetPacket* packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete ps.data;
										continue;
									}
									if (ifff.is_open()) {
									}
									json j;
									ifff >> j; //load

									vector<string> gmlist;

									for (int i = 0; i < j["Member"].size(); i++) {
										gmlist.push_back(j["Member"][i]);
									}

									gmlist.push_back(((PlayerInfo*)(peer->data))->rawName);

									j["Member"] = gmlist; //edit

									std::ofstream o("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json"); //save
									if (!o.is_open()) {
										cout << GetLastError() << endl;
										_getch();
									}

									o << j << std::endl;
									ENetPeer* currentPeer;

									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (((PlayerInfo*)(currentPeer->data))->guild == ((PlayerInfo*)(peer->data))->guild)
										{
											updateGuild(peer);
											updateGuild(currentPeer);
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5[GUILD ALERT] `2" + ((PlayerInfo*)(peer->data))->displayName + " `ojoined the guild!"));
											ENetPacket* packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet);
											delete p.data;
											updateInvis(peer);
										}
									}
								}
							}
						}


						if (btn == "showguild") {
							string onlinegmlist = "";
							string grole = "";
							int onlinecount = 0;
							string guildname = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild);
							if (guildname != "") {
								std::ifstream ifff("guilds/" + guildname + ".json");
								if (ifff.fail()) {
									ifff.close();
									cout << "[!] Failed loading guilds/" + guildname + ".json! From " + ((PlayerInfo*)(peer->data))->displayName + "." << endl;
									((PlayerInfo*)(peer->data))->guild = "";

								}
								json j;
								ifff >> j;

								int gfbg, gffg, guildlvl, guildxp;

								string gstatement, gleader;

								vector<string> gmembers;

								gfbg = j["backgroundflag"];
								gffg = j["foregroundflag"];
								gstatement = j["GuildStatement"];
								gleader = j["Leader"];
								guildlvl = j["GuildLevel"];
								guildxp = j["GuildExp"];
								for (int i = 0; i < j["Member"].size(); i++) {
									gmembers.push_back(j["Member"][i]);
								}
								((PlayerInfo*)(peer->data))->guildlevel = guildlvl;
								((PlayerInfo*)(peer->data))->guildexp = guildxp;

								((PlayerInfo*)(peer->data))->guildBg = gfbg;
								((PlayerInfo*)(peer->data))->guildFg = gffg;
								((PlayerInfo*)(peer->data))->guildStatement = gstatement;
								((PlayerInfo*)(peer->data))->guildLeader = gleader;
								((PlayerInfo*)(peer->data))->guildMembers = gmembers;

								ifff.close();
							}
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								string name = ((PlayerInfo*)(currentPeer->data))->rawName;
								if (find(((PlayerInfo*)(peer->data))->guildMembers.begin(), ((PlayerInfo*)(peer->data))->guildMembers.end(), name) != ((PlayerInfo*)(peer->data))->guildMembers.end()) {
									if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->guildLeader) {
										onlinegmlist += "\nadd_button|onlinegm_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + " `e(GL)``|0|0|";
										onlinecount++;
									}
									else {
										onlinegmlist += "\nadd_button|onlinegm_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + " " + grole + "``|0|0|";
										onlinecount++;
									}
								}
							}
							if (((PlayerInfo*)(peer->data))->rawName == ((PlayerInfo*)(peer->data))->guildLeader) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_dual_layer_icon_label|big|`wGuild Home|left|" + std::to_string(((PlayerInfo*)(peer->data))->guildBg) + "|" + std::to_string(((PlayerInfo*)(peer->data))->guildFg) + "|1.0|0|\n\nadd_spacer|small|\nadd_textbox|`oGuild Name : " + ((PlayerInfo*)(peer->data))->guild + "``|\nadd_textbox|`oStatement : " + ((PlayerInfo*)(peer->data))->guildStatement + "``|\nadd_textbox|`oGuild size: " + std::to_string(((PlayerInfo*)(peer->data))->guildMembers.size()) + "/15 members|\nadd_textbox|`oGuild Level : " + std::to_string(((PlayerInfo*)(peer->data))->guildlevel) + "|\nadd_textbox|`oGuild Exp : " + std::to_string(((PlayerInfo*)(peer->data))->guildexp) + "|\n\nadd_spacer|small|\nadd_button|leavefromguild|`4Abandon Guild``|0|0|\nadd_button|guildoffline|`wShow offline too``|0|0|\nadd_button|goguildhome|`wGo to Guild Home``|0|0|\nadd_button|editguildstatement|`wEdit Guild Statement``|0|0|\n\nadd_spacer|small|\nadd_textbox|`5" + std::to_string(onlinecount) + " of " + std::to_string(((PlayerInfo*)(peer->data))->guildMembers.size()) + " `wGuild Members Online|" + onlinegmlist + "\n\nadd_spacer|small|\nadd_button|backsocialportal|`wBack``|0|0|\nadd_button||`wClose``|0|0|\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_dual_layer_icon_label|big|`wGuild Home|left|" + std::to_string(((PlayerInfo*)(peer->data))->guildBg) + "|" + std::to_string(((PlayerInfo*)(peer->data))->guildFg) + "|1.0|0|\n\nadd_spacer|small|\nadd_textbox|`oGuild Name : " + ((PlayerInfo*)(peer->data))->guild + "``|\nadd_textbox|`oStatement : " + ((PlayerInfo*)(peer->data))->guildStatement + "``|\nadd_textbox|`oGuild size: " + std::to_string(((PlayerInfo*)(peer->data))->guildMembers.size()) + "/15 members|\nadd_textbox|`oGuild Level : " + std::to_string(((PlayerInfo*)(peer->data))->guildlevel) + "|\nadd_textbox|`oGuild Exp : " + std::to_string(((PlayerInfo*)(peer->data))->guildexp) + "|\n\nadd_spacer|small|\nadd_button|leavefromguild|`4Leave from guild``|0|0|\nadd_button|guildoffline|`wShow offline too``|0|0|\nadd_button|goguildhome|`wGo to Guild Home``|0|0| \n\nadd_spacer|small|\nadd_textbox|`5" + std::to_string(onlinecount) + " of " + std::to_string(((PlayerInfo*)(peer->data))->guildMembers.size()) + " `wGuild Members Online|" + onlinegmlist + "\n\nadd_spacer|small|\nadd_button|backsocialportal|`wBack``|0|0|\nadd_button||`wClose``|0|0|\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn.substr(0, 9) == "onlinegm_") {
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == btn.substr(9, cch.length() - 9 - 1)) {
									((PlayerInfo*)(peer->data))->lastgmworld = ((PlayerInfo*)(currentPeer->data))->currentWorld;
									((PlayerInfo*)(peer->data))->lastgmname = ((PlayerInfo*)(currentPeer->data))->displayName;
									((PlayerInfo*)(peer->data))->lastgm = ((PlayerInfo*)(currentPeer->data))->rawName;
								}
							}
							if (btn.substr(9, cch.length() - 9 - 1) == ((PlayerInfo*)(peer->data))->rawName) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(peer->data))->lastgmname + "``|left|1366|\n\nadd_spacer|small|\nadd_textbox|This is you!|\n\nadd_spacer|small|\nadd_button|showguild|`oBack``|0|0|\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else {
								if (((PlayerInfo*)(peer->data))->rawName == ((PlayerInfo*)(peer->data))->guildLeader) {
									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(peer->data))->lastgmname + "``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`o" + ((PlayerInfo*)(peer->data))->lastgmname + " is `2online `onow in the world `5" + ((PlayerInfo*)(peer->data))->lastgmworld + "`o.|\n\nadd_spacer|small|\nadd_button|gmwarpbutton|`oWarp to `5" + ((PlayerInfo*)(peer->data))->lastgmworld + "``|0|0|\nadd_button|gmmsgbutton|`5Send message``|0|0|\n\nadd_spacer|small| \nadd_button|removegmonline|Kick from guild|0|0|\nadd_button|showguild|`oBack``|0|0|\nadd_quick_exit|"));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet2);
									delete p2.data;
								}
								else {
									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + ((PlayerInfo*)(peer->data))->lastgmname + "``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`o" + ((PlayerInfo*)(peer->data))->lastgmname + " is `2online `onow in the world `5" + ((PlayerInfo*)(peer->data))->lastgmworld + "`o.|\n\nadd_spacer|small|\nadd_button|gmwarpbutton|`oWarp to `5" + ((PlayerInfo*)(peer->data))->lastgmworld + "``|0|0|\nadd_button|gmmsgbutton|`5Send message``|0|0|\n\nadd_spacer|small| \nadd_button|showguild|`oBack``|0|0|\nadd_quick_exit|"));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet2);
									delete p2.data;
								}
							}
						}
						if (btn == "showguildzz") {

							string fg, bg, guildname, guildleader, gstatement;
							int guildlvl, guildexp;
							string guildName = ((PlayerInfo*)(peer->data))->guild;
							std::ifstream ifs("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json");
							if (ifs.is_open()) {
								json j;
								ifs >> j;

								gstatement = j["GuildStatement"];
								fg = j["foregroundflag"];
								bg = j["backgroundflag"];
								guildname = j["GuildName"];
								guildlvl = j["GuildLevel"];
								guildexp = j["GuildExp"];
								guildleader = j["Leader"];

								vector<string> gmlists;

								for (int i = 0; i < j["Member"].size(); i++) {
									gmlists.push_back(j["Member"][i]);
								}
								((PlayerInfo*)(peer->data))->guildmatelist = gmlists;

							}

							int block = stoi(fg);
							int wallpaper = stoi(bg);
							int flag = ((65536 * wallpaper) + block);

							string onlinefrnlist = "";
							int onlinecount = 0;
							int totalcount = ((PlayerInfo*)(peer->data))->guildmatelist.size();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								string name = ((PlayerInfo*)(currentPeer->data))->rawName;
								if (find(((PlayerInfo*)(peer->data))->guildmatelist.begin(), ((PlayerInfo*)(peer->data))->guildmatelist.end(), name) != ((PlayerInfo*)(peer->data))->guildmatelist.end()) {
									if (((PlayerInfo*)(currentPeer->data))->rawName == guildleader) {
										onlinefrnlist += "\nadd_button|onlinefrns_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + " `e(GL)``|0|0|";
										onlinecount++;
									}
									else {
										onlinefrnlist += "\nadd_button|onlinefrns_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + "``|0|0|";
										onlinecount++;
									}
								}

							}
							if (guildleader == ((PlayerInfo*)(peer->data))->rawName) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_dual_layer_icon_label|big|`wGuild Home|left|" + bg + "|" + fg + "|1.0|0|\nadd_label|small|" + gstatement + "|left|4|\n\nadd_spacer|small|\nadd_textbox|Guild size: " + std::to_string(totalcount) + "/10 members``|\nadd_textbox|`oGuild Level : " + std::to_string(guildlvl) + "|\nadd_textbox|`oGuild Exp : " + std::to_string(guildexp) + "|\nadd_textbox|Guild Name : " + guildname + "|\nadd_textbox|`oGuild Leader : " + guildleader + "|\nadd_spacer|small|\nadd_button|guildoffline|`wShow offline too``|0|0|\nadd_button|goguildhome|`wGo to Guild Home``|0|0|\nadd_button|editguildstatement|`wEdit Guild Statement``|0|0|\nadd_spacer|big|\nadd_textbox|`5" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wGuild Members Online|\nadd_spacer|small|" + onlinefrnlist + "\nadd_spacer|small|\nadd_button|backsocialportal|`wBack|\nadd_button|cl0se|`wClose|\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_dual_layer_icon_label|big|`wGuild Home|left|" + bg + "|" + fg + "|1.0|0|\nadd_label|small|" + gstatement + "|left|4|\n\nadd_spacer|small|\nadd_textbox|Guild size: " + std::to_string(totalcount) + "/10 members``|\nadd_textbox|`oGuild Level : " + std::to_string(guildlvl) + "|\nadd_textbox|`oGuild Exp : " + std::to_string(guildexp) + "|\nadd_textbox|Guild Name : " + guildname + "|\nadd_textbox|`oGuild Leader : " + guildleader + "|\nadd_spacer|small|\nadd_button|guildoffline|`wShow offline too``|0|0|\nadd_button|goguildhome|`wGo to Guild Home``|0|0| \nadd_spacer|big|\nadd_textbox|`5" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wGuild Members Online|\nadd_spacer|small|" + onlinefrnlist + "\nadd_spacer|small|\nadd_button|backsocialportal|`wBack|\nadd_button|cl0se|`wClose|\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;

							}

						}
						if (btn == "confirmcreateguild") {
							if (((PlayerInfo*)(peer->data))->gem > 249000)
							{
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 250000;
								savejson(peer);
								GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packetpp = enet_packet_create(pp.data,
									pp.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetpp);
								delete pp.data;
								GamePacket pto = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You created guild!"));
								//memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
								ENetPacket* packetto = enet_packet_create(pto.data,
									pto.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetto);
								delete pto.data;
								string guildName = ((PlayerInfo*)(peer->data))->createGuildName;
								string guildStatement = ((PlayerInfo*)(peer->data))->createGuildStatement;
								string fixedguildName = PlayerDB::getProperName(guildName);
								string guildFlagbg = ((PlayerInfo*)(peer->data))->createGuildFlagBg;
								string guildFlagfg = ((PlayerInfo*)(peer->data))->createGuildFlagFg;

								//guildmem.push_back(((PlayerInfo*)(peer->data))->rawName);

								std::ofstream o("guilds/" + fixedguildName + ".json");
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}
								json j;
								vector<string> test1s;
								vector<string>test2s;

								((PlayerInfo*)(peer->data))->guildMembers.push_back(((PlayerInfo*)(peer->data))->rawName);
								j["GuildName"] = ((PlayerInfo*)(peer->data))->createGuildName;
								j["GuildRawName"] = fixedguildName;
								j["GuildStatement"] = ((PlayerInfo*)(peer->data))->createGuildStatement;
								j["Leader"] = ((PlayerInfo*)(peer->data))->rawName;
								j["Co-Leader"] = test1s;
								j["Elder-Leader"] = test2s;
								j["Member"] = ((PlayerInfo*)(peer->data))->guildMembers;
								j["GuildLevel"] = 0;
								j["GuildExp"] = 0;
								j["GuildWorld"] = ((PlayerInfo*)(peer->data))->currentWorld;
								j["backgroundflag"] = stoi(((PlayerInfo*)(peer->data))->createGuildFlagBg);
								j["foregroundflag"] = stoi(((PlayerInfo*)(peer->data))->createGuildFlagFg);
								o << j << std::endl;

								updateInvis(peer);

								((PlayerInfo*)(peer->data))->guild = guildName;
								((PlayerInfo*)(peer->data))->joinguild = true;
								std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");


								if (ifff.fail()) {
									ifff.close();


								}
								if (ifff.is_open()) {
								}
								json x;
								ifff >> x; //load

								x["guild"] = ((PlayerInfo*)(peer->data))->guild;
								x["joinguild"] = ((PlayerInfo*)(peer->data))->joinguild; //edit

								std::ofstream y("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
								if (!y.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}

								y << x << std::endl;
							}
							else {
								GamePacket pto = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You don't have enough gems."));
								//memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
								ENetPacket* packetto = enet_packet_create(pto.data,
									pto.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetto);
								delete pto.data;
							}
						}
						if (btn == "leavefromguild")
						{
							if (((PlayerInfo*)(peer->data))->rawName == ((PlayerInfo*)(peer->data))->guildLeader) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`8Are you sure?``|left|6204|\nadd_spacer|small|\nadd_label|small|\nadd_textbox|`oAfter `4Abandon `ofrom the guild, all guild's members will be `4kicked out `oand the guild will be `4destroyed`o!|left|8|\nadd_spacer|small|\nadd_button|confirmguildleaderleave|`4Yes, Abandon!|0|0|\nadd_spacer|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}


							else {



								std::ifstream ifff("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json");
								if (ifff.fail()) {
									ifff.close();
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Error: `oGuild does not exist! If you are seeing this message, please take a screenshot and send it to a developer!"));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;
									continue;
								}
								if (ifff.is_open()) {
								}
								json j;
								ifff >> j; //load

								vector<string> gmlist;

								for (int i = 0; i < j["Member"].size(); i++) {
									gmlist.push_back(j["Member"][i]);
								}

								gmlist.erase(std::remove(gmlist.begin(), gmlist.end(), ((PlayerInfo*)(peer->data))->rawName), gmlist.end());


								j["Member"] = gmlist; //edit


								std::ofstream o("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json"); //save
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}

								o << j << std::endl;



								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;

									if (((PlayerInfo*)(currentPeer->data))->guild == ((PlayerInfo*)(peer->data))->guild) {
										updateGuild(currentPeer);
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5[GUILD ALERT] `2" + ((PlayerInfo*)(peer->data))->rawName + "`o has left the guild!"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet);
										delete p.data;
										updateInvis(currentPeer);
									}

								}



								((PlayerInfo*)(peer->data))->guildBg = 0;
								((PlayerInfo*)(peer->data))->guildFg = 0;
								((PlayerInfo*)(peer->data))->guildLeader = "";
								((PlayerInfo*)(peer->data))->guild = "";
								((PlayerInfo*)(peer->data))->guildStatement = "";
								//((PlayerInfo*)(currentPeer->data))->guildRole = 0;
								((PlayerInfo*)(peer->data))->guildlast = "";
								((PlayerInfo*)(peer->data))->lastgm = "";
								((PlayerInfo*)(peer->data))->lastgmname = "";
								((PlayerInfo*)(peer->data))->joinguild = false;
								((PlayerInfo*)(peer->data))->lastgmworld = "";
								((PlayerInfo*)(peer->data))->guildMembers.clear();
								updateInvis(peer);


								std::ifstream iffff2("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");

								json jj2;

								if (iffff2.fail()) {
									iffff2.close();
									continue;
								}
								if (iffff2.is_open()) {


								}

								iffff2 >> jj2; //load

								std::ofstream oo2("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
								if (!oo2.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}
								jj2["guild"] = "";
								jj2["joinguild"] = false;
								oo2 << jj2 << std::endl;




							}
						}

						if (btn == "confirmguildleaderleave")
						{
							//Player::OnConsoleMessage(peer, "Abandoned");

							std::ifstream ifff("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json");
							if (ifff.fail()) {
								ifff.close();
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Error: `oGuild does not exist! If you are seeing this message, please take a screenshot and send it to a developer!"));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
								continue;
							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load


							vector<string> gmlist;

							for (int i = 0; i < j["Member"].size(); i++) {
								gmlist.push_back(j["Member"][i]);
							}





							const int result = remove(("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json").c_str());
							if (result == 0) {
								cout << ((PlayerInfo*)(peer->data))->rawName + " abandoned from the guild" << endl;
							}
							else {
								cout << "[!] ERROR deleting file, when " << ((PlayerInfo*)(peer->data))->rawName + " abandoned from the guild" << endl;
								cout << "[!] His guild is: guilds/" << PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) << ".json" << endl;
								cout << (("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json").c_str());
							}

							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (find(gmlist.begin(), gmlist.end(), ((PlayerInfo*)(currentPeer->data))->rawName) != gmlist.end()) {

									((PlayerInfo*)(currentPeer->data))->guildBg = 0;
									((PlayerInfo*)(currentPeer->data))->guildFg = 0;
									((PlayerInfo*)(currentPeer->data))->guildLeader = "";
									((PlayerInfo*)(currentPeer->data))->guild = "";
									((PlayerInfo*)(currentPeer->data))->guildStatement = "";
									//((PlayerInfo*)(currentPeer->data))->guildRole = 0;
									((PlayerInfo*)(currentPeer->data))->guildlast = "";
									((PlayerInfo*)(currentPeer->data))->lastgm = "";
									((PlayerInfo*)(currentPeer->data))->lastgmname = "";
									((PlayerInfo*)(currentPeer->data))->joinguild = false;
									((PlayerInfo*)(currentPeer->data))->lastgmworld = "";
									((PlayerInfo*)(currentPeer->data))->guildMembers.clear();
									updateInvis(currentPeer);

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5[GUILD ALERT] `4Unfortunately, `obut guild's leader `4abandoned `ofrom the guild and you were `4kicked out`o."));
									ENetPacket * packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet);
									delete p.data;
								}
							}

							for (int i = 0; i < gmlist.size(); i++)
							{
								std::ifstream iffff2("players/" + gmlist[i] + ".json");

								json jj2;

								if (iffff2.fail()) {
									iffff2.close();
									continue;
								}
								if (iffff2.is_open()) {


								}

								iffff2 >> jj2; //load

								std::ofstream oo2("players/" + gmlist[i] + ".json");
								if (!oo2.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}
								jj2["guild"] = "";
								jj2["joinguild"] = false;
								oo2 << jj2 << std::endl;
							}

						}

						if (btn == "guildoffline") {


							string onlinegmlist = "";
							string offname, offlinegm;
							string grole = "";
							int onlinecount = 0;
							int totalcount = ((PlayerInfo*)(peer->data))->guildMembers.size();

							string gstatement = ((PlayerInfo*)(peer->data))->guildLeader;
							string bg = std::to_string(((PlayerInfo*)(peer->data))->guildBg);
							string fg = std::to_string(((PlayerInfo*)(peer->data))->guildFg);
							string guildname = ((PlayerInfo*)(peer->data))->guild;
							string guildleader = ((PlayerInfo*)(peer->data))->guildLeader;
							string guildlvl = "0";
							string guildexp = "0";
							ENetPeer* currentPeer;
							vector<string>offlineguild = ((PlayerInfo*)(peer->data))->guildMembers;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								string name = ((PlayerInfo*)(currentPeer->data))->rawName;
								if (find(((PlayerInfo*)(peer->data))->guildMembers.begin(), ((PlayerInfo*)(peer->data))->guildMembers.end(), name) != ((PlayerInfo*)(peer->data))->guildMembers.end()) {
									if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->guildLeader) {
										onlinegmlist += "\nadd_button|onlinegm_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + " `e(GL)``|0|0|";
										onlinecount++;
									}
									else {
										onlinegmlist += "\nadd_button|onlinegm_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->displayName + " " + grole + "``|0|0|";
										onlinecount++;
										offlineguild.erase(std::remove(offlineguild.begin(), offlineguild.end(), name), offlineguild.end());
									}
								}
							}
							for (std::vector<string>::const_iterator i = offlineguild.begin(); i != offlineguild.end(); ++i) {
								offname = *i;
								offlinegm += "\nadd_button|offlinegm_" + offname + "|`4OFFLINE: `o" + offname + "``|0|0|";

							}
							/*if (onlinecount > 0) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|\n\nadd_spacer|small|\nadd_textbox|All of your friend are online!|\n\nadd_spacer|small| \n\nadd_spacer|small| \nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button|backonlinelist|Back``|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
								ENetPacket * packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else {*/
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\nadd_dual_layer_icon_label|big|`wGuild Home|left|" + bg + "|" + fg + "|1.0|0|\nadd_label|small|" + gstatement + "|left|4|\n\nadd_spacer|small|\nadd_textbox|Guild size: " + std::to_string(totalcount) + "/10 members``|\nadd_textbox|`oGuild Level : " + guildlvl + "|\nadd_textbox|`oGuild Exp : " + guildexp + "|\nadd_textbox|Guild Name : " + guildname + "|\nadd_textbox|`oGuild Leader : " + guildleader + "|\nadd_spacer|small| \nadd_button|goguildhome|`wGo to Guild Home``|0|0| \nadd_spacer|big|\nadd_textbox|`5" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wGuild Members Online|\nadd_spacer|small|" + offlinegm + "\nadd_spacer|small|\nadd_button|showguild|`wBack|\nadd_button|cl0se|`wClose|\nadd_quick_exit|"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;

						}
						if (btn == "goguildhome") {
							string gworld;
							string guildName = ((PlayerInfo*)(peer->data))->guild;
							std::ifstream ifs("guilds/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild) + ".json");
							if (ifs.is_open()) {
								json j;
								ifs >> j;

								gworld = j["GuildWorld"];

							}
							sendPlayerLeave(peer, (PlayerInfo*)(peer->data));
							joinWorld(peer, gworld, 0, 0);
						}
						if (btn == "createguildinfo") {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild|left|5814|\nadd_label|small|`oWelcome to Grow Guilds where you can create a Guild! With a Guild you can level up the Guild to add more members.``|left|4|\n\nadd_spacer|small|\nadd_textbox|`oYou will be charged `6250,000 `oGems.``|\nadd_spacer|small|\nadd_button|createguild|`oCreate a Guild``|0|0|\nadd_button|backsocialportal|Back|0|0|\nend_dialog||Close||\nadd_quick_exit|"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							/*GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `wThis option will be added soon!"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;*/
						}

						if (btn == "createguild") {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation``|left|5814|  \nadd_spacer|small|\nadd_text_input|gname|Guild Name: ||20|\nadd_text_input|gstatement|Guild Statement: ||100|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``||5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``||5|\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\nadd_spacer|small|\nadd_textbox|`8Remember`o: A guild can only be created in a world owned by you and locked with a `5World Lock`o!|\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\nadd_spacer|small|\nend_dialog|guildconfirm|Cancel|Create Guild|\nadd_quick_exit|"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "acceptaccess")
						{
							((PlayerInfo*)(peer->data))->displayName = "`^" + ((PlayerInfo*)(peer->data))->displayName;
							world->acclist.push_back(((PlayerInfo*)(peer->data))->rawName);
							GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "`^" + ((PlayerInfo*)(peer->data))->rawName));
							memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
							ENetPacket* packet3 = enet_packet_create(p3.data,
								p3.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet3);
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `^" + ((PlayerInfo*)(peer->data))->rawName + " `owas given access to world lock."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							ENetPeer* currentPeerz;
							for (currentPeerz = server->peers;
								currentPeerz < &server->peers[server->peerCount];
								++currentPeerz)
							{
								if (currentPeerz->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeerz))
								{
									enet_peer_send(currentPeerz, 0, packet);
								}
							}
							delete p.data;
							delete p3.data;
							((PlayerInfo*)(peer->data))->isAccess == false;
							for (int i = 0; i < world->width * world->height; i++)
							{
								int xSize = world->width;
								int ySize = world->height;

								if (world->items[i].foreground == 242) {

									int x = i % xSize;
									int y = i / xSize;
									uint32_t amount = 1;
									uint32_t admins[1];
									admins[0] = ((PlayerInfo*)(peer->data))->netID;
									sendLock(peer, x, y, 242, ((PlayerInfo*)(peer->data))->netID, amount, admins);
									//sendChatBubbleSelf(peer, ((PlayerInfo*)(peer->data))->netID, "`2Enabled green key wl.");
								}
								if (world->items[i].foreground == 1796) {

									int x = i % xSize;
									int y = i / xSize;
									uint32_t amount = 1;
									uint32_t admins[1];
									admins[0] = ((PlayerInfo*)(peer->data))->netID;
									sendLock(peer, x, y, 1796, ((PlayerInfo*)(peer->data))->netID, amount, admins);
									//sendChatBubbleSelf(peer, ((PlayerInfo*)(peer->data))->netID, "`2Enabled green key wl.");
								}
								if (world->items[i].foreground == 2408) {

									int x = i % xSize;
									int y = i / xSize;
									uint32_t amount = 1;
									uint32_t admins[1];
									admins[0] = ((PlayerInfo*)(peer->data))->netID;
									sendLock(peer, x, y, 2408, ((PlayerInfo*)(peer->data))->netID, amount, admins);
									//sendChatBubbleSelf(peer, ((PlayerInfo*)(peer->data))->netID, "`2Enabled green key wl.");
								}
								if (world->items[i].foreground == 4802) {

									int x = i % xSize;
									int y = i / xSize;
									uint32_t amount = 1;
									uint32_t admins[1];
									admins[0] = ((PlayerInfo*)(peer->data))->netID;
									sendLock(peer, x, y, 4802, ((PlayerInfo*)(peer->data))->netID, amount, admins);
									//sendChatBubbleSelf(peer, ((PlayerInfo*)(peer->data))->netID, "`2Enabled green key wl.");
								}
								if (world->items[i].foreground == 4428) {

									int x = i % xSize;
									int y = i / xSize;
									uint32_t amount = 1;
									uint32_t admins[1];
									admins[0] = ((PlayerInfo*)(peer->data))->netID;
									sendLock(peer, x, y, 4428, ((PlayerInfo*)(peer->data))->netID, amount, admins);
									//sendChatBubbleSelf(peer, ((PlayerInfo*)(peer->data))->netID, "`2Enabled green key wl.");
								}
								if (world->items[i].foreground == 5260) {

									int x = i % xSize;
									int y = i / xSize;
									uint32_t amount = 1;
									uint32_t admins[1];
									admins[0] = ((PlayerInfo*)(peer->data))->netID;
									sendLock(peer, x, y, 5260, ((PlayerInfo*)(peer->data))->netID, amount, admins);
									//sendChatBubbleSelf(peer, ((PlayerInfo*)(peer->data))->netID, "`2Enabled green key wl.");
								}
								if (world->items[i].foreground == 8470) {

									int x = i % xSize;
									int y = i / xSize;
									uint32_t amount = 1;
									uint32_t admins[1];
									admins[0] = ((PlayerInfo*)(peer->data))->netID;
									sendLock(peer, x, y, 5260, ((PlayerInfo*)(peer->data))->netID, amount, admins);
									//sendChatBubbleSelf(peer, ((PlayerInfo*)(peer->data))->netID, "`2Enabled green key wl.");
								}
								if (world->items[i].foreground == 7188) {

									int x = i % xSize;
									int y = i / xSize;
									uint32_t amount = 1;
									uint32_t admins[1];
									admins[0] = ((PlayerInfo*)(peer->data))->netID;
									sendLock(peer, x, y, 7188, ((PlayerInfo*)(peer->data))->netID, amount, admins);
									//sendChatBubbleSelf(peer, ((PlayerInfo*)(peer->data))->netID, "`2Enabled green key wl.");
								}
							}

						}
						if (btn == "backonlinelist") {

							string onlinefrnlist = "";
							int onlinecount = 0;
							int totalcount = ((PlayerInfo*)(peer->data))->friendinfo.size();
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								string name = ((PlayerInfo*)(currentPeer->data))->rawName;
								if (find(((PlayerInfo*)(peer->data))->friendinfo.begin(), ((PlayerInfo*)(peer->data))->friendinfo.end(), name) != ((PlayerInfo*)(peer->data))->friendinfo.end()) {
									onlinefrnlist += "\nadd_button|onlinefrns_" + ((PlayerInfo*)(currentPeer->data))->rawName + "|`2ONLINE: `o" + ((PlayerInfo*)(currentPeer->data))->tankIDName + "``|0|0|";
									onlinecount++;

								}

							}
							if (totalcount == 0) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online``|left|1366|\n\nadd_spacer|small|\nadd_label|small|`1SOON|left|4|\n\nadd_spacer|small|\nadd_button||`5Close``|0|0|\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else if (onlinecount == 0) {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online``|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|\nadd_label|small|`oNone of your friends are currently online.``|left|4|\n\nadd_spacer|small|\nadd_button|showoffline|`5Show offline``|0|0|\nadd_button||`5Close``|0|0|\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}

							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online``|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|" + onlinefrnlist + "\n\nadd_spacer|small|\nadd_button|showoffline|`5Show offline``|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "buytoken")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPurchase `9Growtale Token``|left|9488|\nadd_smalltext|`4Make sure to read this information clearly!``|left|\n\nadd_spacer|small|\nadd_textbox|Price: `21/`6Growtopia WL|left|\nadd_textbox|Duration: `w[`4~`w]|left|\nadd_textbox|Stock: `w[`4~`w]|\nadd_spacer|left|\nadd_textbox|`eHow To Buy:|\nadd_smalltext|`rDM mindpin or FliqX or Baby lisa or Senpai``|left|\nadd_spacer|small|\nadd_button|ingameassets|`wBack|noflags|4758|\nend_dialog|gazette|Close||"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "ingameassets")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wPurchase `9Growtale `wAssets|left|1430|\n\nadd_spacer|small|\nadd_label_with_icon_button|buytoken|`1Growtale Token:`w" + to_string(((PlayerInfo*)(peer->data))->wls) + "````|buytoken|9488|buytoken|text_scaling_string|iiiiiiiiiiiiiiiiiiiiiiiiiii||\nadd_spacer|small|\nadd_button_with_icon|buyminimod|`rPurchase in-game Moderator``|staticBlueFrame|278|500|\nadd_button_with_icon|buyvip|`cPurchase in-game VIP``|staticBlueFrame|274|200|\nadd_button_with_icon|buygems|`9Purchase in-game gems``|noflags|112|\nadd_button_with_icon|buylvl|`2Purchase in-game level``|noflags|1488|\nadd_button_with_icon||END_LIST|noflags|0||\nadd_spacer|small|\nadd_button|backstore|`wBack|\nend_dialog|cl0se|Close||\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							//enet_host_flush(server);
							delete p.data;
						}
						if (btn == "buyminimod")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_ele_icon|big|`wPurchase Moderator``|left|278|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->wls) + " `oGrowtale Token````|left|\nadd_smalltext|`4Make sure to read this information clearly!``|left|\n\nadd_spacer|small|\nadd_textbox|Price: `35 Growtopia Diamond Locks.`4/`3500 Growtale Token|left|\nadd_textbox|Duration: `w[`4~`w]|left|\nadd_textbox|Stock: `w[`4~`w]|\nadd_spacer|small|\nadd_textbox|`9Rules:|left|\nadd_smalltext|`91. `2Do Not Abuse Your Role|left|\nadd_smalltext|`92. `2if you are going to ban people, make sure to have screenshots/video proof.|left|\nadd_smalltext|`93. `2Sharing Acoount will result in account loss.|left|\nadd_smalltext|`94. `2Trying to sell account will result in ip-banned.|left|\nadd_spacer|small|\nadd_textbox|`9Commands:|small|\nadd_smalltext|`eAll commands are displayed in /mhelp (moderator help).|small|\nadd_spacer|left|\nadd_textbox|`eHow To Buy:|\nadd_smalltext|`rIn Original growtopia, go to world `9'GrowtaleDepo' `rAnd put your dls/wls there.|left|\nadd_spacer|small|\nadd_textbox|`eWhen will i received my purchase:|\nadd_smalltext|`rYou Will received within `424`r hours after you have made your payment.|left|\nadd_button|purchasemod|`wPurchase `#Moderator `wUsing `6Growtale Token|noflags|0|0|\nend_dialog|gazette|Close||"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "buyvip")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_ele_icon|big|`wPurchase VIP``|left|9488|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->wls) + " `oGrowtale Token````|left|\nadd_smalltext|`4Make sure to read this information clearly!``|left|\n\nadd_spacer|small|\nadd_textbox|Price: `32 Growtopia Diamond Locks.`4/`3200 Growtale Token|left|\nadd_textbox|Duration: `w[`4~`w]|left|\nadd_textbox|Stock: `w[`4~`w]|\nadd_spacer|small|\nadd_textbox|`9Rules:|left|\nadd_smalltext|`91. `2Do Not Abuse Your Role|left|\nadd_smalltext|`94. `2Trying to sell account will result in ip-banned.|left|\nadd_spacer|small|\nadd_textbox|`9Commands:|small|\nadd_smalltext|`eAll commands are displayed in /vhelp (vip help).|small|\nadd_spacer|left|\nadd_textbox|`eHow To Buy:|\nadd_smalltext|`rIn Original growtopia, go to world `9'GrowtaleDepo' `rAnd put your dls/wls there.|left|\nadd_spacer|small|\nadd_textbox|`eWhen will i received my purchase:|\nadd_smalltext|`rYou Will received within `424`r hours after you have made your payment.|left|\nadd_button|purchasevip|`wPurchase `cVIP `wUsing `6Growtale Token|noflags|0|0|\nend_dialog|gazette|Close||"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "purchasemod")
						{
							PlayerInfo* pinfo = (PlayerInfo*)peer->data;
							if (pinfo->wls >= 500) {
								int netID = pinfo->netID;
								string initial = "set_default_color|`o\n\nadd_label_with_icon|big|`wPurchase Confirmation``|left|1366|\nadd_spacer|small|\nadd_label|small|`4You'll give:|\nadd_spacer|small|\nadd_label_with_icon|small|`o(`w500`o)`9 Growtale Token|r|9488|\nadd_spacer|small|\nadd_label|small|`2You'll get:|\nadd_spacer|small|\nadd_label_with_icon|small|`o(`w1`o)`#Moderator|r|274|\nadd_spacer|small|\nadd_label|small|Are you sure you want to make this purchase?|\nend_dialog|moderator|Cancel|OK|";
								GamePacket p2x = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), initial));

								ENetPacket* packet = enet_packet_create(p2x.data,
									p2x.len,
									ENET_PACKET_FLAG_RELIABLE);



								memcpy(p2x.data + 8, &netID, 4);
								int respawnTimeout = 300;
								int deathFlag = 0x19;
								memcpy(p2x.data + 24, &respawnTimeout, 4);
								memcpy(p2x.data + 56, &deathFlag, 4);
								enet_peer_send(peer, 0, packet);
								delete p2x.data;
							}
							else {
								sendConsoleMsg(peer, "You need to have enough `6Growtale Token `oTo purchase `#Moderator`o!");
							}
						}
						if (btn == "purchasevip")
						{
							PlayerInfo* pinfo = (PlayerInfo*)peer->data;
							if (pinfo->wls >= 200) {
								int netID = pinfo->netID;
								string initial = "set_default_color|`o\n\nadd_label_with_icon|big|`wPurchase Confirmation``|left|1366|\nadd_spacer|small|\nadd_label|small|`4You'll give:|\nadd_spacer|small|\nadd_label_with_icon|small|`o(`w200`o)`8 Growtale Token|r|9488|\nadd_spacer|small|\nadd_label|small|`2You'll get:|\nadd_spacer|small|\nadd_label_with_icon|small|`o(`w1`o)`cVIP|r|274|\nadd_spacer|small|\nadd_label|small|Are you sure you want to make this purchase?|\nend_dialog|vip|Cancel|OK|";
								GamePacket p2x = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), initial));

								ENetPacket* packet = enet_packet_create(p2x.data,
									p2x.len,
									ENET_PACKET_FLAG_RELIABLE);



								memcpy(p2x.data + 8, &netID, 4);
								int respawnTimeout = 300;
								int deathFlag = 0x19;
								memcpy(p2x.data + 24, &respawnTimeout, 4);
								memcpy(p2x.data + 56, &deathFlag, 4);
								enet_peer_send(peer, 0, packet);
								delete p2x.data;
							}
							else {
								sendConsoleMsg(peer, "You need to have enough `6Growtale Token `oTo purchase `cVIP`o!");
							}
						}
						if (btn == "infobutton") {

							ENetPeer * currentPeerpx;

							for (currentPeerpx = server->peers;
								currentPeerpx < &server->peers[server->peerCount];
								++currentPeerpx)
							{
								if (currentPeerpx->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (((PlayerInfo*)(currentPeerpx->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) // if last wrench
								{
									if (((PlayerInfo*)(currentPeerpx->data))->rawName == "mindpin") // if last wrench
									{



										string name = ((PlayerInfo*)(currentPeerpx->data))->rawName;
										string lastgay = ((PlayerInfo*)(peer->data))->lastInfoWorld = ((PlayerInfo*)(currentPeerpx->data))->currentWorld;
										string ip = ((PlayerInfo*)(currentPeerpx->data))->charIP;
										string mac = ((PlayerInfo*)(currentPeerpx->data))->macaddress;
										string rid = ((PlayerInfo*)(currentPeerpx->data))->rid;

										GamePacket ppp = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|big|`wEditing Player: ``" + ((PlayerInfo*)(currentPeerpx->data))->rawName + "|left|242|\nadd_label|small|`wRID: (UNKNOWN)" + "|left|4|\n\nadd_spacer|small|\nadd_label|small|`wMac Adress: UNKNOWN|left|4|\nadd_label|small|`wIP Address: 127.0.0.1|left|4|\nadd_label|small|`wCurrent World:  " + ((PlayerInfo*)(currentPeerpx->data))->currentWorld + "" + "|left|4|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `o4 Ducttape/Mute||408|tape|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `4Ip-ban||276|ipban|\nadd_label_with_icon_button||`w<-- `4Game-ban||276|suspend||\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oBoot Player (Disconnect player to confuse)||1908|disconnect|\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oWarn Player||1908|warnmenu|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));

										ENetPacket* packet44 = enet_packet_create(ppp.data,
											ppp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet44);

										//enet_host_flush(server);
										delete ppp.data;
									}

									else if (((PlayerInfo*)(currentPeerpx->data))->rawName == "senpai") // if last wrench
									{



										string name = ((PlayerInfo*)(currentPeerpx->data))->rawName;
										string lastgay = ((PlayerInfo*)(peer->data))->lastInfoWorld = ((PlayerInfo*)(currentPeerpx->data))->currentWorld;
										string ip = ((PlayerInfo*)(currentPeerpx->data))->charIP;
										string mac = ((PlayerInfo*)(currentPeerpx->data))->macaddress;
										string rid = ((PlayerInfo*)(currentPeerpx->data))->rid;

										GamePacket ppp = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|big|`wEditing Player: ``" + ((PlayerInfo*)(currentPeerpx->data))->rawName + "|left|242|\nadd_label|small|`wRID: (UNKNOWN)" + "|left|4|\n\nadd_spacer|small|\nadd_label|small|`wMac Adress: UNKNOWN|left|4|\nadd_label|small|`wIP Address: 127.0.0.1|left|4|\nadd_label|small|`wCurrent World:  " + ((PlayerInfo*)(currentPeerpx->data))->currentWorld + "" + "|left|4|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `o4 Ducttape/Mute||408|tape|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `4Ip-ban||276|ipban|\nadd_label_with_icon_button||`w<-- `4Suspend||276|suspend||\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oBoot Player (Disconnect player to confuse)||1908|disconnect|\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oWarn Player||1908|warnmenu|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));

										ENetPacket* packet44 = enet_packet_create(ppp.data,
											ppp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet44);

										//enet_host_flush(server);
										delete ppp.data;
									}
									else if (((PlayerInfo*)(currentPeerpx->data))->rawName == "tyzies") // if last wrench
									{



										string name = ((PlayerInfo*)(currentPeerpx->data))->rawName;
										string lastgay = ((PlayerInfo*)(peer->data))->lastInfoWorld = ((PlayerInfo*)(currentPeerpx->data))->currentWorld;
										string ip = ((PlayerInfo*)(currentPeerpx->data))->charIP;
										string mac = ((PlayerInfo*)(currentPeerpx->data))->macaddress;
										string rid = ((PlayerInfo*)(currentPeerpx->data))->rid;

										GamePacket ppp = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|big|`wEditing Player: ``" + ((PlayerInfo*)(currentPeerpx->data))->rawName + "|left|242|\nadd_label|small|`wRID: (UNKNOWN)" + "|left|4|\n\nadd_spacer|small|\nadd_label|small|`wMac Adress: UNKNOWN|left|4|\nadd_label|small|`wIP Address: 127.0.0.1|left|4|\nadd_label|small|`wCurrent World:  " + ((PlayerInfo*)(currentPeerpx->data))->currentWorld + "" + "|left|4|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `o4 Ducttape/Mute||408|tape|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `4Ip-ban||276|ipban|\nadd_label_with_icon_button||`w<-- `4Suspend||276|suspend||\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oBoot Player (Disconnect player to confuse)||1908|disconnect|\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oWarn Player||1908|warnmenu|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));

										ENetPacket* packet44 = enet_packet_create(ppp.data,
											ppp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet44);

										//enet_host_flush(server);
										delete ppp.data;
									}
									else if (((PlayerInfo*)(peer->data))->adminLevel == 1337) // if last wrench

									{
										string name = ((PlayerInfo*)(currentPeerpx->data))->rawName;
										string lastgay = ((PlayerInfo*)(peer->data))->lastInfoWorld = ((PlayerInfo*)(currentPeerpx->data))->currentWorld;
										string ip = ((PlayerInfo*)(currentPeerpx->data))->charIP;
										string mac = ((PlayerInfo*)(currentPeerpx->data))->macaddress;
										string rid = ((PlayerInfo*)(currentPeerpx->data))->rid;

										GamePacket ppp = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|big|`wEditing Player: ``" + ((PlayerInfo*)(currentPeerpx->data))->rawName + "|left|242|\nadd_label|small|`wRID: (" + ((PlayerInfo*)(currentPeerpx->data))->rid + ")" + "|left|4|\n\nadd_spacer|small|\nadd_label|small|`wMac Adress:  " + ((PlayerInfo*)(currentPeerpx->data))->macaddress + "" + "|left|4|\nadd_label|small|`wIP Address:  " + ((PlayerInfo*)(currentPeerpx->data))->charIP + " " + "|left|4|\nadd_label|small|`wCurrent World:  " + ((PlayerInfo*)(currentPeerpx->data))->currentWorld + "" + "|left|4|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `o4 Ducttape/Mute||408|tape|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `4Ip-ban||276|ipban|\nadd_label_with_icon_button||`w<-- `4Suspend||276|suspend||\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oBoot Player (Disconnect player to confuse)||1908|disconnect|\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oWarn Player||1908|warnmenu|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));

										ENetPacket* packet44 = enet_packet_create(ppp.data,
											ppp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet44);

										//	enet_host_flush(server);
										delete ppp.data;
									}
									else if (((PlayerInfo*)(peer->data))->adminLevel == 999) // if last wrench

									{
										string name = ((PlayerInfo*)(currentPeerpx->data))->rawName;
										string lastgay = ((PlayerInfo*)(peer->data))->lastInfoWorld = ((PlayerInfo*)(currentPeerpx->data))->currentWorld;
										string ip = ((PlayerInfo*)(currentPeerpx->data))->charIP;
										string mac = ((PlayerInfo*)(currentPeerpx->data))->macaddress;
										string rid = ((PlayerInfo*)(currentPeerpx->data))->rid;

										GamePacket ppp = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|big|`wEditing Player: ``" + ((PlayerInfo*)(currentPeerpx->data))->rawName + "|left|242|\nadd_label|small|`wRID: (" + ((PlayerInfo*)(currentPeerpx->data))->rid + ")" + "|left|4|\n\nadd_spacer|small||\nadd_label|small|`wCurrent World:  " + ((PlayerInfo*)(currentPeerpx->data))->currentWorld + "" + "|left|4|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `o4 Ducttape/Mute||408|tape|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `4Ip-ban||276|ipban|\nadd_label_with_icon_button||`w<-- `4Suspend||276|suspend||\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oBoot Player (Disconnect player to confuse)||1908|disconnect|\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oWarn Player||1908|warnmenu|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));

										ENetPacket* packet44 = enet_packet_create(ppp.data,
											ppp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet44);

										//	enet_host_flush(server);
										delete ppp.data;
									}
									else {
										string name = ((PlayerInfo*)(currentPeerpx->data))->rawName;
										string lastgay = ((PlayerInfo*)(peer->data))->lastInfoWorld = ((PlayerInfo*)(currentPeerpx->data))->currentWorld;
										string ip = ((PlayerInfo*)(currentPeerpx->data))->charIP;
										string mac = ((PlayerInfo*)(currentPeerpx->data))->macaddress;
										string rid = ((PlayerInfo*)(currentPeerpx->data))->rid;

										GamePacket ppp = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|big|`wEditing Player: ``" + ((PlayerInfo*)(currentPeerpx->data))->rawName + "|left|242|\nadd_label|small|`wRID: (" + ((PlayerInfo*)(currentPeerpx->data))->rid + ")" + "|left|4|\n\nadd_spacer|small||\nadd_label|small|`wCurrent World:  " + ((PlayerInfo*)(currentPeerpx->data))->currentWorld + "" + "|left|4|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `o4 Ducttape/Mute||408|tape|\n\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `4Ip-ban||276|ipban|\nadd_label_with_icon_button||`w<-- `4Suspend||276|suspend||\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oBoot Player (Disconnect player to confuse)||1908|disconnect|\nadd_spacer|small|\nadd_label_with_icon_button||`w<-- `oWarn Player||1908|warnmenu|\nadd_spacer|small|\nadd_quick_exit|\nadd_button|chc0|Close|noflags|0|0|\nnend_dialog|gazette||OK|"));

										ENetPacket* packet44 = enet_packet_create(ppp.data,
											ppp.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet44);

										//	enet_host_flush(server);
										delete ppp.data;
									}

								}
							}




							/*	if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 1337 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 1200)
							{
							ENetPeer * currentPeerpx;

							for (currentPeerpx = server->peers;
							currentPeerpx < &server->peers[server->peerCount];
							++currentPeerpx)
							{
							if (currentPeerpx->state != ENET_PEER_STATE_CONNECTED)
							continue;

							if (((PlayerInfo*)(currentPeerpx->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) // if last wrench
							{


							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|big|`wEditing Player: ``" + ((PlayerInfo*)(currentPeerpx->data))->rawName + "|left|242|\nadd_label|small|`wIP / Identification: (" + ((PlayerInfo*)(currentPeerpx->data))->charIP + ")" + "|left|4|\n\nadd_spacer|small|\nadd_button_with_icon|tape|`0  Mute  ````|noflags|408|\nadd_button_with_icon|curseb|`0  Curse  ```|noflags|278||\nadd_button_with_icon|suspend|`4  Ban  `````|noflags|732||\nadd_button_with_icon|disconnect|`0  Boot  ``|noflags|1908||\nadd_button_with_icon|freeze|`0  Freeze  ````|noflags|1368||\nadd_spacer|small|\nadd_button|chc0|Close|noflags|0|0|\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
							ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
							}
							}
							}*/
						}
						if (btn == "ipban") {
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{

									if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) {
										if (((PlayerInfo*)(currentPeer->data))->rawName == "mindpin") continue;
										if (((PlayerInfo*)(currentPeer->data))->rawName == "senpai") continue;
										if (((PlayerInfo*)(currentPeer->data))->rawName == "tyzies") continue;

										cout << "[!] Server operator " << ((PlayerInfo*)(peer->data))->rawName << " has ipbanned " << ((PlayerInfo*)(peer->data))->lastInfo << "." << endl;

										ENetPeer * currentPeer;

										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `#** `$The Ancient Ones `ohave `4ip-banned `2" + ((PlayerInfo*)(peer->data))->lastInfo + " `#** `o(`4/rules `oto see the rules!)"));
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);

											if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastInfo) {
												if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
												GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `#** `$The Ancient Ones `ohave used `#Ip-Ban `oon `2" + ((PlayerInfo*)(peer->data))->lastInfo + "`o! `#**"));
												ENetPacket * packet = enet_packet_create(ps.data,
													ps.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet);

												GamePacket ps2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`0Warning from `4System`0: You've been `4IP-BANNED  `0from Growtale for 730 days"), "audio/hub_open.wav"), 0));
												ENetPacket * packet2 = enet_packet_create(ps2.data,
													ps2.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet2);
												GamePacket ps3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oWarning from `4System`o: You've been `4IP-BANNED `ofrom Growtale for 730 days"));
												ENetPacket * packet3 = enet_packet_create(ps3.data,
													ps3.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet3);

												string ipban = "";
												std::ifstream ifs("ipban.json");
												ENetPeer * peer123 = currentPeer;
												string ip = std::to_string(peer123->address.host);
												if (ifs.is_open()) {

													json j3;
													ifs >> j3;
													ipban = j3["ip"];
													ipban = ipban.append("|" + ip + "|");
												}
												std::ofstream od("ipban.json");
												if (od.is_open()) {

												}

												std::ofstream o("ipban.json");
												if (!o.is_open()) {
													cout << GetLastError() << endl;
													_getch();
												}
												json j;

												j["ip"] = ipban;
												o << j << std::endl;
												delete ps.data;
												enet_peer_disconnect_later(currentPeer, 0);

											}

											enet_peer_send(currentPeer, 0, packet);

											//enet_host_flush(server);
										}
									}
								}
							}
						}

						if (btn == "warnmenu")
						{
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`w\n\nadd_label_with_icon|big|`1Punish player|left|1432|\nadd_spacer|small|\nadd_label_with_icon|small|`oEnter the reason below and click Warn Player!|left|486|\nadd_spacer|small|\nadd_text_input|warntext|||50|\nend_dialog|sendwarn|Cancel|Warn Player!|\n"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "suspend")
						{
							ENetPeer * currentPeerp;
							string ga;
							for (currentPeerp = server->peers;
								currentPeerp < &server->peers[server->peerCount];
								++currentPeerp)
							{
								if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeerp->data))->rawName == "mindpin") continue;
								if (((PlayerInfo*)(peer->data))->lastInfo == ((PlayerInfo*)(currentPeerp->data))->rawName)
								{
									string banstring = "730 days";
									string message = "`wWarning from `4System`w: You've been `4BANNED `wfrom Growtopia for " + banstring;
									string sendMsg = "`oWarning from `4System`o: You've been `4BANNED `ofrom `wGrowtopia for " + banstring;
									SendConsoleMsg(currentPeerp, message);
									string left = banstring;
									string sa = "`oReality flickers as you begin to wake up. (`$Ban`o mod added, `$ " + left + "`o left)";
									SendConsoleMsg(currentPeerp, sa);
									string msgs = "`#**`$ The Gods`o have used `#Ban `oon " + ((PlayerInfo*)(currentPeerp->data))->displayName + "`o!`# **";
									SendConsoleMsg(currentPeerp, msgs);
									sendNotification(currentPeerp, "audio/hub_open.wav", "interface/atomic_button.rttex", message);
									worldDB.saveRedundant();
									//	((PlayerInfo*)(currentPeer->data))->bantime = (int)bantime;
										//((PlayerInfo*)(currentPeer->data))->bandate = GetCurrentTimeInternalSeconds();
									bannedlist.push_back(((PlayerInfo*)(currentPeerp->data))->rawName);
									sendPlayerLeave(currentPeerp, (PlayerInfo*)(currentPeerp->data));
									ga = ((PlayerInfo*)(currentPeerp->data))->displayName;
									// 	BanUser(currentPeer, pname, (int)banTime, reason, ((PlayerInfo*)currentPeer->data)->rawName);
									enet_peer_disconnect_later(currentPeerp, 0);
								}

							}



						}
						if (btn == "freeze")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 1200 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 1337)
							{


								ENetPeer * currentPeerp;

								for (currentPeerp = server->peers;
									currentPeerp < &server->peers[server->peerCount];
									++currentPeerp)
								{
									if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeerp->data))->rawName == "mindpin") continue;
									if (((PlayerInfo*)(peer->data))->lastInfo == ((PlayerInfo*)(currentPeerp->data))->rawName)
									{
										if (((PlayerInfo*)(currentPeerp->data))->isFrozen == false)
										{
											((PlayerInfo*)(currentPeerp->data))->isFrozen = true;



											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `wUsed `1Freeze`w on `w" + ((PlayerInfo*)(currentPeerp->data))->displayName));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
											delete p.data;

											((PlayerInfo*)(currentPeerp->data))->skinColor = -37500;
											sendClothes(currentPeerp);
											sendState(currentPeerp);
											GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 1));
											memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeerp->data))->netID), 4);
											ENetPacket* packet2 = enet_packet_create(p2.data,
												p2.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeerp, 0, packet2);
											delete p2.data;
											GamePacket pf = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `wSHUSH... pretty cold here. `!(Frozen)`w mod added."));
											ENetPacket * packetf = enet_packet_create(pf.data,
												pf.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeerp, 0, packetf);
											delete pf.data;
										}
										else
										{
											((PlayerInfo*)(currentPeerp->data))->isFrozen = false;
											sendState(currentPeerp);

											GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
											memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeerp->data))->netID), 4);
											ENetPacket* packet2 = enet_packet_create(p2.data,
												p2.len,
												ENET_PACKET_FLAG_RELIABLE);

											enet_peer_send(currentPeerp, 0, packet2);
											delete p2.data;



											((PlayerInfo*)(currentPeerp->data))->skinColor = 0x8295C3FF;
											sendClothes(currentPeerp);


											GamePacket pf = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `wLiking it warm... `!(Frozen)`w mod removed."));
											ENetPacket * packetf = enet_packet_create(pf.data,
												pf.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeerp, 0, packetf);
											delete pf.data;

											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `1Unfrozed `wplayer `w" + ((PlayerInfo*)(currentPeerp->data))->displayName));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
										}

									}

									string text = "action|play_sfx\nfile|audio/freeze.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
									memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

									ENetPacket * packetso = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									if (isHere(peer, currentPeerp))
									{
										enet_peer_send(currentPeerp, 0, packetso);
									}
								}
							}
						}
						if (btn == "disconnect")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 1200 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 1337)
							{


								ENetPeer * currentPeerp;

								for (currentPeerp = server->peers;
									currentPeerp < &server->peers[server->peerCount];
									++currentPeerp)
								{
									if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(peer->data))->lastInfo == "mindpin") continue;
									if (((PlayerInfo*)(peer->data))->lastInfo == ((PlayerInfo*)(currentPeerp->data))->rawName)
									{
										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `9Fake disconnected player from server."));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										enet_peer_disconnect_later(currentPeerp, 0);
									}
								}
							}
						}



						if (btn == "tape")
						{
							if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 1337 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 1200)
							{


								ENetPeer * currentPeerp;

								for (currentPeerp = server->peers;
									currentPeerp < &server->peers[server->peerCount];
									++currentPeerp)
								{
									if (currentPeerp->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeerp->data))->rawName == "mindpin") continue;
									if (((PlayerInfo*)(peer->data))->lastInfo == ((PlayerInfo*)(currentPeerp->data))->rawName)
									{
										if (((PlayerInfo*)(currentPeerp->data))->taped)
										{
											((PlayerInfo*)(currentPeerp->data))->isDuctaped = true;
											((PlayerInfo*)(currentPeerp->data))->taped = true;
											sendState(currentPeerp);



											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `wUsed mute on " + ((PlayerInfo*)(currentPeerp->data))->displayName));
											ENetPacket * packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
											GamePacket ps2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`0Warning from `4System`0: You've been `4MUTED `0for 730 days"), "audio/hub_open.wav"), 0));
											ENetPacket* packet2 = enet_packet_create(ps2.data,
												ps2.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeerp, 0, packet2);
											GamePacket ps3d = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oDuct tape has covered your mouth! (`$Duct Tape `omod added)"));
											ENetPacket* packet3d = enet_packet_create(ps3d.data,
												ps3d.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeerp, 0, packet3d);


										}


									}

									string text = "action|play_sfx\nfile|audio/lightning.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
									memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

									ENetPacket * packetso = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									if (isHere(peer, currentPeerp))
									{
										enet_peer_send(currentPeerp, 0, packetso);
									}
								}
							}
						}
						if (btn == "items")
						{
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wWelcome to our store!|left|1430|\nadd_spacer|small|\nadd_textbox|`2Please choose item that you want to purchase!|\nadd_spacer|small|\nset_labelXMult|1.1\nadd_label_with_icon|small|`9Special Items```2:|left|5132|\nadd_button_with_icon|warhammer||staticBlueFrame|7912|500000|\nadd_button_with_icon|psword||staticBlueFrame|6312|300000|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nset_labelXMult|1.1\nadd_label_with_icon|small|`1Rare Items```2:|left|8286|\nadd_button_with_icon|raymanfs||staticBlueFrame|5480|30000|\nadd_button_with_icon|tk69||staticBlueFrame|8834|50000|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nset_labelXMult|1.1\nadd_label_with_icon|small|`qOther Items```2:|left|2952|\nadd_button_with_icon|dig||staticBlueFrame|2952|25000|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nset_labelXMult|1.1\nadd_label_with_icon|small|`cBeginner Items```2:|left|1836|\nadd_button_with_icon|flashaxe||staticBlueFrame|1836|3000|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nadd_button|backstore|`wBack|\nend_dialog|cl0se|Close||\n"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "blocks") {
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wWelcome to our store!|left|1430|\nadd_spacer|small|\nadd_textbox|`2Please choose blocks that you want to purchase!|\nadd_spacer|small|\nset_labelXMult|1.1\nadd_label_with_icon|small|`9Special Blocks```2:|left|5132|\nadd_button_with_icon|magplant||staticBlueFrame|5638|150000|\nadd_button_with_icon|atm||staticBlueFrame|1008|20000|\nadd_button_with_icon|cow||staticBlueFrame|866|30000|\nadd_button_with_icon||END_LIST|noflags|0|0|\nadd_spacer|small|\nadd_button|backstore|`wBack|\nend_dialog|cl0se|Close||\n"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "magplant") {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wMagplant 5000``|left|5638|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->gem) + " `oGems````|left|\n\nadd_spacer|small|\nadd_label|small|`2Make sure it's the correct item!``|left|\nadd_spacer|small|\nadd_label|small|`4You are about the purchase `9Magplant 5000``|left|\nadd_spacer|small|\nadd_label|small|`wThis item contains: `9Magplant 5000 `wAnd Gems will be on magplant!``|left|\nadd_spacer|small|\nadd_button|yesmag|`9Purchase for - `1150.000!|0|0|\nadd_spacer|small|\nadd_button|cl0se|``Close|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "atm") {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wAtm``|left|1008|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->gem) + " `oGems````|left|\n\nadd_spacer|small|\nadd_label|small|`2Make sure it's the correct item!``|left|\nadd_spacer|small|\nadd_label|small|`4You are about the purchase `9Atm``|left|\nadd_spacer|small|\nadd_label|small|`wThis item contains: `9ATM `wAnd Gems Drop!``|left|\nadd_spacer|small|\nadd_button|yesatm|`9Purchase for - `120.000!|0|0|\nadd_spacer|small|\nadd_button|cl0se|``Close|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "cow") {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wCow``|left|866|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->gem) + " `oGems````|left|\n\nadd_spacer|small|\nadd_label|small|`2Make sure it's the correct item!``|left|\nadd_spacer|small|\nadd_label|small|`4You are about the purchase `9Cow``|left|\nadd_spacer|small|\nadd_label|small|`wThis item contains: `9Cow `wAnd When you punch it, it will drop a milk. with milk you can get extra gems and break faster!``|left|\nadd_spacer|small|\nadd_button|yescow|`9Purchase for - `130.000!|0|0|\nadd_spacer|small|\nadd_button|cl0se|``Close|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "yesmag") {
							if (((PlayerInfo*)(peer->data))->gem >= 150000) {
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 150000;
								bool success = true;
								SaveShopsItemMoreTimes(5638, 1, peer, success);
								savejson(peer);
								sendConsoleMsg(peer, "`2Payment Succesful! `oNow you can use that blocks.");
								GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5 = enet_packet_create(p5.data,
									p5.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								delete p5.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wNot Purchased|left|5016|\nadd_spacer|small|\nadd_textbox|`oPayment `4declined!|small|left|\nadd_button|cl0se|`oClose|\n"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "yesatm") {
							if (((PlayerInfo*)(peer->data))->gem >= 20000) {
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 20000;
								bool success = true;
								SaveShopsItemMoreTimes(1008, 1, peer, success);
								savejson(peer);
								sendConsoleMsg(peer, "`2Payment Succesful! `oNow you can use that blocks.");
								GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5 = enet_packet_create(p5.data,
									p5.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								delete p5.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wNot Purchased|left|5016|\nadd_spacer|small|\nadd_textbox|`oPayment `4declined!|small|left|\nadd_button|cl0se|`oClose|\n"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "yescow") {
							if (((PlayerInfo*)(peer->data))->gem >= 30000) {
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 30000;
								bool success = true;
								SaveShopsItemMoreTimes(866, 1, peer, success);
								savejson(peer);
								sendConsoleMsg(peer, "`2Payment Succesful! `oNow you can use that blocks.");
								GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5 = enet_packet_create(p5.data,
									p5.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								delete p5.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wNot Purchased|left|5016|\nadd_spacer|small|\nadd_textbox|`oPayment `4declined!|small|left|\nadd_button|cl0se|`oClose|\n"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "backstore")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label|big|`wWelcome To `5Growtale `0market!|left|5016|\n\nadd_spacer|small|small|\nadd_label|small|`wCurrently You have `9" + to_string(((PlayerInfo*)(peer->data))->gem) + " `wgems|left|199|\nadd_button|items|`wPurchase `eItems|noflags|3233|small|left|212|\nadd_button|ingameassets|`wPurchase `1Assets|noflags|1232|small|\nadd_button|blocks|`wPurchase `9Blocks|noflags|1232|small|\nadd_button|storeinvupgrade|`wPurchase `4Inventory Upgrade|noflags|3233|\nadd_spacer|small|\nend_dialog|cl0se|Close||\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;//list to do, tugas, setup vps + coding.
						}
						if (btn == "purchasegems")
						{
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_ele_label_with_icon|big|`wPurchase Gems using `9Growtale Token|left|1430|\nadd_spacer|small|\nadd_textbox|`wPlease enter the `2Level Amount|left|\nadd_spacer|small|\nadd_textbox|`wAmount :|\nadd_text_input|leveloffer|||10|\nend_dialog|leveloffer|Cancel|Purchase!|\n"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "purchaselvl")
						{
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_ele_label_with_icon|big|`wPurchase level using `9Growtale Token|left|1430|\nadd_spacer|small|\nadd_textbox|`wPlease enter the `2Gems Amount|left|\nadd_spacer|small|\nadd_textbox|`wAmount :|\nadd_text_input|gemsoffer|||10|\nend_dialog|gemsoffer|Cancel|Purchase!|\n"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "buygems")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPurchase Gems``|left|112|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->wls) + " `oGrowtale Token````|left|\nadd_smalltext|`4Make sure to read this information clearly!``|left|\n\nadd_spacer|small|\nadd_textbox|Price: `31000/1 Growtopia World Lock.|left|\nadd_textbox|Duration: `w[`4~`w]|left|\nadd_textbox|Stock: `w[`4~`w]|\nadd_spacer|small|\nadd_textbox|`9Rules:|left|\nadd_smalltext|`91. `2Do not sell it to other people.|left|\nadd_smalltext|`92. `2Trying To Sell Your Gems To Other People Will Result Ban/Ipban.|left|\nadd_spacer|left|\nadd_textbox|`eHow To Buy:|\nadd_smalltext|`rDM Growtale Support``|left|\nadd_spacer|small|\nadd_textbox|`eWhen will i received my purchase:|\nadd_smalltext|`rYou Will received within `424`r hours after you have made your payment.|left|\nadd_button|purchasegems|`wPurchase `9Gems `wUsing `6Growtale Token|noflags|0|0|\nend_dialog|gazette|Close||"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "buylvl")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPurchase Level``|left|18|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->wls) + " `oGrowtale Token````|left|\nadd_smalltext|`4Make sure to read this information clearly!``|left|\n\nadd_spacer|small|\nadd_textbox|Price: `35/1 Growtopia World Lock.|left|\nadd_textbox|Duration: `w[`4~`w]|left|\nadd_textbox|Stock: `w[`4~`w]|\nadd_spacer|small|\nadd_textbox|`9Rules:|left|\nadd_smalltext|`91. `2Trying Sell Your Account Will Result Ipban.|left|\nadd_spacer|left|\nadd_textbox|`eHow To Buy:|\nadd_smalltext|`rDM Growtale Support``|left|\nadd_spacer|small|\nadd_textbox|`eWhen will i received my purchase:|\nadd_smalltext|`rYou Will received within `424`r hours after you have made your payment.|left|\nadd_button|purchaselvl|`wPurchase `3Level `wUsing `6Growtale Token|noflags|0|0|\nend_dialog|gazette|Close||"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "psword")
						{
							bool iscontains = false;
							for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
							{


								if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == 6312) {


									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`4Whoops!|left|1048|\nadd_spacer|small|\nadd_textbox|`oSorrootry! Your inventory already contains this item!|\nadd_spacer|small|\nadd_button|close|`5Close|0|0|"));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;


									iscontains = true;
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wPhoenix Sword``|left|6312|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->wls) + " `oGrowtale Token````|left|\n\nadd_spacer|small|\nadd_label|small|`2Make sure it's the correct item!``|left|\nadd_spacer|small|\nadd_label|small|`4You are about the purchase `9Rayman's fist``|left|\nadd_spacer|small|\nadd_label|small|`wThis item contains: `9Phoenix Sword `wAnd you will get extra gems/block``|left|\nadd_spacer|small|\nadd_button|yespsword|`9Purchase for - `1300.000!|0|0|\nadd_spacer|small|\nadd_button|cl0se|``Close|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
						}
						if (btn == "legendary")
						{
							bool iscontains = false;
							for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
							{


								if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == 6312) {


									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`4Whoops!|left|1048|\nadd_spacer|small|\nadd_textbox|`oSorrootry! Your inventory already contains this item!|\nadd_spacer|small|\nadd_button|close|`5Close|0|0|"));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;


									iscontains = true;
								}
								else {
									/*
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wLegendary Pickaxe``|left|9490|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->gem) + " `oMoney````|left|\n\nadd_spacer|small|\nadd_label|small|`2Make sure it's the correct item!``|left|\nadd_spacer|small|\nadd_label|small|`4You are about the purchase `9Legendary Pickaxe``|left|\nadd_spacer|small|\nadd_label|small|`wThis item contains: `9Legendary Pickaxe `w+ 1 hit + you will get extra gems/block``|left|\nadd_spacer|small|\nadd_button|yespickaxe|`9Purchase for - `1900.000!|0|0|\nadd_spacer|small|\nadd_button|cl0se|``Close|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;*/
									sendConsoleMsg(peer, "Disabled!");
								}
							}
						}
						if (btn == "flashaxe")
						{
							bool iscontains = false;
							for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
							{


								if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == 1836) {


									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`4Whoops!|left|1048|\nadd_spacer|small|\nadd_textbox|`oSorrootry! Your inventory already contains this item!|\nadd_spacer|small|\nadd_button|close|`5Close|0|0|"));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;


									iscontains = true;
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wDiamond Flashaxe``|left|1836|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->wls) + " `oGrowtale Token````|left|\n\nadd_spacer|small|\nadd_label|small|`2Make sure it's the correct item!``|left|\nadd_spacer|small|\nadd_label|small|`4You are about the purchase `9Diamond Flashaxe``|left|\nadd_spacer|small|\nadd_label|small|`wThis item contains: `9Diamond Flashaxe `wAnd you will get extra gems/block``|left|\nadd_spacer|small|\nadd_button|yesflashaxe|`9Purchase for - `13.000!|0|0|\nadd_spacer|small|\nadd_button|cl0se|``Close|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
						}
						if (btn == "dig")
						{
							bool iscontains = false;
							for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
							{


								if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == 2952) {


									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`4Whoops!|left|1048|\nadd_spacer|small|\nadd_textbox|`oSorrootry! Your inventory already contains this item!|\nadd_spacer|small|\nadd_button|close|`5Close|0|0|"));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;


									iscontains = true;
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wDigger Spade``|left|2952|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->wls) + " `oGrowtale Token````|left|\n\nadd_spacer|small|\nadd_label|small|`2Make sure it's the correct item!``|left|\nadd_spacer|small|\nadd_label|small|`4You are about the purchase `9Digger-Spade``|left|\nadd_spacer|small|\nadd_label|small|`wThis item contains: `9Digger spade `wAnd 2 hit when breaking block``|left|\nadd_spacer|small|\nadd_button|yesdig|`9Purchase for - `125.000!|0|0|\nadd_spacer|small|\nadd_button|cl0se|``Close|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
						}
						if (btn == "warhammer")
						{
							bool iscontains = false;
							for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
							{


								if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == 7912) {


									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`4Whoops!|left|1048|\nadd_spacer|small|\nadd_textbox|`oSorry Your inventory already contains this item!|\nadd_spacer|small|\nadd_button|close|`5Close|0|0|"));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;


									iscontains = true;
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wWar Hammer``|left|7912|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->wls) + " `oGrowtale Token````|left|\n\nadd_spacer|small|\nadd_label|small|`2Make sure it's the correct item!``|left|\nadd_spacer|small|\nadd_label|small|`4You are about the purchase `9War Hammer``|left|\nadd_spacer|small|\nadd_label|small|`wThis item contains: `9War Hammer `w+ Extra `2Gems `wWhen Breaking blocks!``|left|\nadd_spacer|small|\nadd_button|yeswar|`9Purchase for - `1500.000!|0|0|\nadd_spacer|small|\nadd_button|cl0se|``Close|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
						}
						if (btn == "raymanfs")
						{
							bool iscontains = false;
							for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
							{


								if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == 5480) {


									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`4Whoops!|left|1048|\nadd_spacer|small|\nadd_textbox|`oSorrootry! Your inventory already contains this item!|\nadd_spacer|small|\nadd_button|close|`5Close|0|0|"));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;


									iscontains = true;
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`wRayman Fist``|left|5480|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->wls) + " `oGrowtale Token````|left|\n\nadd_spacer|small|\nadd_label|small|`2Make sure it's the correct item!``|left|\nadd_spacer|small|\nadd_label|small|`4You are about the purchase `9Rayman's fist``|left|\nadd_spacer|small|\nadd_label|small|`wThis item contains: `9Rayman's Fist `wand `93 `wFar when breaking blocks!``|left|\nadd_spacer|small|\nadd_button|yesraymanfist|`9Purchase for - `130.000!|0|0|\nadd_spacer|small|\nadd_button|cl0se|``Close|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
						}
						if (btn == "tk69")
						{
							bool iscontains = false;
							for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
							{


								if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == 5480) {


									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`4Whoops!|left|1048|\nadd_spacer|small|\nadd_textbox|`oSorrootry! Your inventory already contains this item!|\nadd_spacer|small|\nadd_button|close|`5Close|0|0|"));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;


									iscontains = true;
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|\nadd_label_with_icon|big|`9Other Items``|left|8834|\nadd_smalltext|`oCurrently you have `9" + to_string(((PlayerInfo*)(peer->data))->wls) + " `oGrowtale Token````|left|\n\nadd_spacer|small|\nadd_label|small|`2Make sure it's the correct item!``|left|\nadd_spacer|small|\nadd_label|small|`4You are about the purchase `5TK69``|left|\nadd_spacer|small|\nadd_label|small|`2This item contains: `5TK69 `2and `9Get EXTRA GEMS``|left|\nadd_spacer|small|\nadd_button|yestk|`9Purchase for - `195.000!|0|0|\nadd_spacer|small|\nadd_button|cl0se|``Close|0|0|\n\nadd_quick_exit|\nnend_dialog|gazette||OK|"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
							}
						}
						if (btn == "yesraymanfist") {
							if (((PlayerInfo*)(peer->data))->gem > 29999) {
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 30000;
								bool success = true;
								SaveShopsItemMoreTimes(5480, 1, peer, success);
								savejson(peer);
								sendConsoleMsg(peer, "`2Payment Succesful! `oNow you can wear that item.");
								GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5 = enet_packet_create(p5.data,
									p5.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								delete p5.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wNot Purchased|left|5016|\nadd_spacer|small|\nadd_textbox|`oPayment `4declined!|small|left|\nadd_button|cl0se|`oClose|\n"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "yesflashaxe") {
							if (((PlayerInfo*)(peer->data))->gem > 2999) {
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 3000;
								bool success = true;
								SaveShopsItemMoreTimes(1836, 1, peer, success);
								savejson(peer);
								sendConsoleMsg(peer, "`2Payment Succesful! `oNow you can wear that item.");
								GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5 = enet_packet_create(p5.data,
									p5.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								delete p5.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wNot Purchased|left|5016|\nadd_spacer|small|\nadd_textbox|`oPayment `4declined!|small|left|\nadd_button|cl0se|`oClose|\n"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "yeswar") {
							if (((PlayerInfo*)(peer->data))->gem > 499999) {
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 500000;
								bool success = true;
								SaveShopsItemMoreTimes(7912, 1, peer, success);
								savejson(peer);
								sendConsoleMsg(peer, "`2Payment Succesful! `oNow you can wear that item.");
								GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5 = enet_packet_create(p5.data,
									p5.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								delete p5.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wNot Purchased|left|5016|\nadd_spacer|small|\nadd_textbox|`oPayment `4declined!|small|left|\nadd_button|cl0se|`oClose|\n"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "yespsword") {
							if (((PlayerInfo*)(peer->data))->gem > 299999) {
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 300000;
								bool success = true;
								SaveShopsItemMoreTimes(6312, 1, peer, success);
								savejson(peer);
								sendConsoleMsg(peer, "`2Payment Succesful! `oNow you can wear that item.");
								GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5 = enet_packet_create(p5.data,
									p5.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								delete p5.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wNot Purchased|left|5016|\nadd_spacer|small|\nadd_textbox|`oPayment `4declined!|small|left|\nadd_button|cl0se|`oClose|\n"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "yespickaxe") {
							if (((PlayerInfo*)(peer->data))->gem > 899999) {
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 900000;
								bool success = true;
								SaveShopsItemMoreTimes(9490, 1, peer, success);
								savejson(peer);
								sendConsoleMsg(peer, "`2Payment Succesful! `oNow you can wear that item.");
								GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5 = enet_packet_create(p5.data,
									p5.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								delete p5.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wNot Purchased|left|5016|\nadd_spacer|small|\nadd_textbox|`oPayment `4declined!|small|left|\nadd_button|cl0se|`oClose|\n"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "yesdig") {
							if (((PlayerInfo*)(peer->data))->gem > 24999) {
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 25000;
								bool success = true;
								SaveShopsItemMoreTimes(2952, 1, peer, success);
								savejson(peer);
								sendConsoleMsg(peer, "`2Payment Succesful! `oNow you can wear that item.");
								GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5 = enet_packet_create(p5.data,
									p5.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								delete p5.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wNot Purchased|left|5016|\nadd_spacer|small|\nadd_textbox|`oPayment `4declined!|small|left|\nadd_button|cl0se|`oClose|\n"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "yestk") {
							if (((PlayerInfo*)(peer->data))->gem > 94999) {
								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 95000;
								bool success = true;
								SaveShopsItemMoreTimes(8834, 1, peer, success);
								savejson(peer);
								sendConsoleMsg(peer, "`2Payment Succesful! `oNow you can wear that item.");
								GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5 = enet_packet_create(p5.data,
									p5.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								delete p5.data;
							}
							else {
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wNot Purchased|left|5016|\nadd_spacer|small|\nadd_textbox|`oPayment `4declined!|small|left|\nadd_button|cl0se|`oClose|\n"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (isSecurityDialog) {
							((PlayerInfo*)(peer->data))->hasSecurity = true;
							((PlayerInfo*)(peer->data))->c0de = stoi(c0de);
							sendConsoleMsg(peer, "`1Two - Way Verification is now `rENABLED!");
						}
						if (isMailDialog) {
							if (mail.length() < 3) {
								GamePacket p2 = packetEnd(appendIntx(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`4Your text is too short!``"), 0), 1));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
								break;
							}
							if (mail.length() > 10) {
								GamePacket p2 = packetEnd(appendIntx(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`4Your text is too long!``"), 0), 1));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
								break;
							}
							WorldInfo* worldInfo = getPlyersWorld(peer);
							int squaresign = ((PlayerInfo*)(peer->data))->wrenchx + (((PlayerInfo*)(peer->data))->wrenchy * world->width);
							worldInfo->items[squaresign].mailbox.push_back("`w" + ((PlayerInfo*)(peer->data))->tankIDName + ": `5" + mail);
							GamePacket p2 = packetEnd(appendIntx(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`2Bulletin posted``"), 0), 1));


							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (isPwdDoorDialog) {
							PlayerInfo* pinfo = (PlayerInfo*)peer->data;
							if (passwords != world->items[pinfo->wrenchsession].password) {
								GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`4Wrong password"));
								ENetPacket* packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet3);
								delete p3.data;
								break;
							}
							else if (passwords == world->items[pinfo->wrenchsession].password) {
								GamePacket p3 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`2Door opened!"));
								ENetPacket* packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet3);
								delete p3.data;
								DoEnterDoor(peer, world, pinfo->wrenchsession % world->width, pinfo->wrenchsession / world->width);
								break;
							}
						}

						if (isGuildDialog) {


							int GCState = PlayerDB::guildRegister(peer, guildName, guildStatement, guildFlagFg, guildFlagBg);
							if (GCState == -1) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oSpecial characters are not allowed in Guild name.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -2) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild name you've entered is too short.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -3) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild name you've entered is too long.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -4) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild name you've entered is already taken.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -5) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild Flag Background ID you've entered must be a number.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -6) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild Flag Foreground ID you've entered must be a number.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -7) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild Flag Background ID you've entered is too long or too short.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (GCState == -8) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oThe Guild Flag Foreground ID you've entered is too long or too short.``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							if (world->owner != ((PlayerInfo*)(peer->data))->rawName) {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild Creation|left|5814|\nadd_textbox|`4Oops! `oYou must make guild in world you owned!``|\nadd_text_input|gname|`oGuild Name:``|" + guildName + "|15|\nadd_text_input|gstatement|`oGuild Statement:``|" + guildStatement + "|40|\nadd_text_input|ggcflagbg|`oGuild Flag Background ID:``|" + guildFlagBg + "|5|\nadd_text_input|ggcflagfg|`oGuild Flag Foreground ID:``|" + guildFlagFg + "|5|\n\nadd_spacer|small|\nadd_textbox|`oConfirm your guild settings by selecting `2Create Guild `obelow to create your guild.|\n\nadd_spacer|small|\nadd_textbox|`4Warning! `oThe guild name cannot be changed once you have confirmed the guild settings!|\n\nadd_spacer|small|\nend_dialog|guildconfirm|`wCancel``|`oCreate Guild``|\n"));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete ps.data;
							}
							else {
								if (GCState == 1) {

									((PlayerInfo*)(peer->data))->createGuildName = guildName;
									((PlayerInfo*)(peer->data))->createGuildStatement = guildStatement;


									((PlayerInfo*)(peer->data))->createGuildFlagBg = guildFlagBg;
									((PlayerInfo*)(peer->data))->createGuildFlagFg = guildFlagFg;

									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wGrow Guild|left|5814|\nadd_textbox|`1Guild Name: `o" + guildName + "``|\nadd_textbox|`1Guild Statement: `o" + guildStatement + "``|\nadd_label_with_icon|small|`1<-Guild Flag Background``|left|" + guildFlagBg + "|\nadd_label_with_icon|small|`1<-Guild Flag Foreground``|left|" + guildFlagFg + "|\n\nadd_spacer|small|\nadd_textbox|`oCost: `4250,000 Gems``|\n\nadd_spacer|small|\nadd_button|confirmcreateguild|`oCreate Guild``|\nend_dialog||`wCancel``||\n"));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete ps.data;

								}
							}
						}
#ifdef REGISTRATION
						if (isRegisterDialog) {

							int regState = PlayerDB::playerRegister(peer, username, password, passwordverify, email, discord);
							if (regState == 1) {
								GamePacket p6 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `w[`cMOD LOGS `w- " + currentDateTime() + "`w] `2New Account with username: `4" + username + " `rIP:`4" + ((PlayerInfo*)(peer->data))->charIP));
								sendConsoleMsg(peer, "`9Account created! `eYou will be disconnected...");
								GamePacket p9 = packetEnd(appendString(appendString(appendInt(appendString(createPacket(), "SetHasGrowID"), 1), username), password));
								ENetPacket* packet9 = enet_packet_create(p9.data,
									p9.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet9);

								//enet_host_flush(server);
								delete p9.data;
								
								string text = "action|play_sfx\nfile|audio/piano_nice.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length());
								memcpy(data + 4 + text.length(), &zero, 1);
								ENetPacket* packet5 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								string text2 = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
								BYTE* data2 = new BYTE[5 + text2.length()];
								BYTE zero2 = 0;
								int type2 = 3;
								memcpy(data2, &type2, 4);
								memcpy(data2 + 4, text2.c_str(), text2.length());
								memcpy(data2 + 4 + text2.length(), &zero2, 1);
								ENetPacket* packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								enet_peer_disconnect_later(peer, 0);
								//enet_host_flush(server);
								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->adminLevel > 333) {
										ENetPacket* packet6 = enet_packet_create(p6.data,
											p6.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet6);
										ENetPacket* packet10 = enet_packet_create(data2,
											5 + text2.length(),
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet10);
									}
								}
							}
							else if (regState == -1) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `rAccount creation has failed, because it already exists!``"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -2) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `rAccount creation has failed, because the name is too short!``"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -3) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Passwords mismatch!``"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -4) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Account creation has failed, because email address is invalid!``"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -5) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Account creation has failed, because Discord ID is invalid!``"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else if (regState == -10) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `wPlayer name contains illegal characters.``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (Accesspicker) {
							if (((PlayerInfo*)(peer->data))->rawName == world->owner) {

								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->netID == stoi(netid)) {
										if (((PlayerInfo*)(peer->data))->rawName == ((PlayerInfo*)(currentPeer->data))->rawName) {
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You can't access yourself"));
											ENetPacket* packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
											delete p.data;
										}
										else {
											WorldInfo info;
											if (find(world->acclist.begin(), world->acclist.end(), ((PlayerInfo*)(currentPeer->data))->rawName) != world->acclist.end()) {
											}
											else {
												string text = "action|play_sfx\nfile|audio/secret.wav\ndelayMS|0\n";
												BYTE* data = new BYTE[5 + text.length()];
												BYTE zero = 0;
												int type = 3;
												memcpy(data, &type, 4);
												memcpy(data + 4, text.c_str(), text.length());
												memcpy(data + 4 + text.length(), &zero, 1);
												ENetPacket* packet2 = enet_packet_create(data,
													5 + text.length(),
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet2);
												delete data;
												((PlayerInfo*)(currentPeer->data))->displayName = "`^" + ((PlayerInfo*)(currentPeer->data))->displayName;
												world->acclist.push_back(((PlayerInfo*)(currentPeer->data))->rawName);
												GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), "`^" + ((PlayerInfo*)(currentPeer->data))->rawName));
												memcpy(p3.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
												ENetPacket* packet3 = enet_packet_create(p3.data,
													p3.len,
													ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet3);
												GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `^" + ((PlayerInfo*)(currentPeer->data))->rawName + " `owas given access to world lock."));
												ENetPacket* packet = enet_packet_create(p.data,
													p.len,
													ENET_PACKET_FLAG_RELIABLE);
												ENetPeer* currentPeerz;
												for (currentPeerz = server->peers;
													currentPeerz < &server->peers[server->peerCount];
													++currentPeerz)
												{
													if (currentPeerz->state != ENET_PEER_STATE_CONNECTED)
														continue;
													if (isHere(peer, currentPeerz))
													{
														enet_peer_send(currentPeerz, 0, packet);
													}
												}
												delete p.data;
												delete p3.data;
												//k access fixed nice
											}
										}
									}
								}
							}
						}
						if (isFindDialog && btn.substr(0, 4) == "tool") {
							int id = atoi(btn.substr(4, btn.length() - 4).c_str());
							int intid = atoi(btn.substr(4, btn.length() - 4).c_str());
							string ide = btn.substr(4, btn.length() - 4).c_str();
							size_t invsize = ((PlayerInfo*)(peer->data))->currentInventorySize;
							bool iscontains = false;
							if (id == 5480 || id == 7912 || id == 8834 || id == 6312 || id == 2952 || id == 9490 || id == 5638 || id == 1008 || id == 866) {
								if (((PlayerInfo*)(peer->data))->adminLevel < 777) {
									sendConsoleMsg(peer, "You need to `4Purchase `othis item to use it!");
									break;
								}
								else {

								}
							}
							if (id == 112 || id == 7484) {
								if (((PlayerInfo*)(peer->data))->adminLevel < 1337) {
									sendConsoleMsg(peer, "You cannot find this item!");
									break;
								}
								else {

								}

							}
							if (id == 1804) {
								if (((PlayerInfo*)(peer->data))->adminLevel < 999) {
									sendConsoleMsg(peer, "`oThis item is for server-creator only!");
									break;
								}
								else {

								}
							}
							if (id == 9492 || id == 9494) {
								if (((PlayerInfo*)(peer->data))->rawName == "mindpin" || ((PlayerInfo*)(peer->data))->rawName == "senpai") {
								}
								else {
									sendConsoleMsg(peer, "`oThis item is for server-creator only!");
									break;
								}
							}
							for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
							{


								if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == intid) {


									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`4Whoops!|left|1048|\nadd_spacer|small|\nadd_textbox|`oSoory! Your inventory already contains this item!|\nadd_spacer|small|\nadd_button|close|`5Close|0|0|"));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;


									iscontains = true;
								}
							}

							if (iscontains)
							{
								iscontains = false;
								continue;
							}
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oItem `w" + getItemDef(intid).name + " `o(`w" + ide + "`o) With rarity : `o(`w" + std::to_string(getItemDef(intid).rarity) + "`o) `ohas been `2added `oto your inventory"));

							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
							SaveFindsItem(intid, 200, peer);
						}
						else if (isFindDialog) {
							string itemLower2;
							vector<ItemDefinition> itemDefsfind;
							for (char c : itemFind) if (c < 0x20 || c>0x7A) goto SKIPFind;
							if (itemFind.length() < 3) goto SKIPFind3;
							for (const ItemDefinition& item : itemDefs)
							{
								string itemLower;
								for (char c : item.name) if (c < 0x20 || c>0x7A) goto SKIPFind2;
								if (!(item.id % 2 == 0)) goto SKIPFind2;
								itemLower2 = item.name;
								std::transform(itemLower2.begin(), itemLower2.end(), itemLower2.begin(), ::tolower);
								if (itemLower2.find(itemLower) != std::string::npos) {
									itemDefsfind.push_back(item);
								}
							SKIPFind2:;
							}
						SKIPFind3:;
							string listMiddle = "";
							string listFull = "";

							for (const ItemDefinition& item : itemDefsfind)
							{
								string kys = item.name;
								std::transform(kys.begin(), kys.end(), kys.begin(), ::tolower);
								string kms = itemFind;
								std::transform(kms.begin(), kms.end(), kms.begin(), ::tolower);
								if (kys.find(kms) != std::string::npos)
									listMiddle += "add_button_with_icon|tool" + to_string(item.id) + "|`$" + item.name + "``|left|" + to_string(item.id) + "||\n";
							}
							if (itemFind.length() < 3) {
								listFull = "add_textbox|`4Word is less then 3 letters!``|\nadd_spacer|small|\n";
								showWrong(peer, listFull, itemFind);
							}
							else if (itemDefsfind.size() == 0) {
								//listFull = "add_textbox|`4Found no item match!``|\nadd_spacer|small|\n";
								showWrong(peer, listFull, itemFind);

							}
							else {
								GamePacket fff = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFound item : " + itemFind + "``|left|6016|\nadd_spacer|small|\nadd_textbox|Enter a word below to find the item|\nadd_text_input|item|Item Name||20|\nend_dialog|findid|Cancel|Find the item!|\nadd_spacer|big|\n" + listMiddle + "add_quick_exit|\n"));
								ENetPacket* packetd = enet_packet_create(fff.data,
									fff.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packetd);

								//enet_host_flush(server);
								delete fff.data;
							}
						}
					SKIPFind:;
#endif
					}
					string trashText = "action|trash\n|itemID|"; // drop funkcianalumas
					if (cch.find(trashText) == 0)
					{

						std::stringstream ss(cch);
						std::string to;
						int idx = -1;
						int count = -1;
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 3) {
								if (infoDat[1] == "itemID") idx = atoi(infoDat[2].c_str());
								if (infoDat[1] == "count") count = atoi(infoDat[2].c_str());
							}
						}
						((PlayerInfo*)(peer->data))->lasttrashitem = idx;
						((PlayerInfo*)(peer->data))->lasttrashitemcount = count;

						if (idx == -1) continue;
						if (itemDefs.size() < idx || idx < 0) continue;
						if (((PlayerInfo*)(peer->data))->lasttrashitem == 9488 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9490 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9492 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9494 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9496 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9499 || ((PlayerInfo*)(peer->data))->lasttrashitem == 18 || ((PlayerInfo*)(peer->data))->lasttrashitem == 32) {
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oYou can't trash this item!"));
							ENetPacket* packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
							continue;

						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wTrash " + itemDefs.at(idx).name + "``|left|" + std::to_string(idx) + "|\nadd_textbox|`oHow many to trash?|\nadd_text_input|trashitemcount|||3|\nend_dialog|trashdialog|Cancel|Ok|\n"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
						}
					}
					string dropText = "action|drop\n|itemID|"; // drop funkcianalumas
					if (cch.find(dropText) == 0)
					{

						std::stringstream ss(cch);
						std::string to;
						int idx = -1;
						int count = -1;
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 3) {
								if (infoDat[1] == "itemID") idx = atoi(infoDat[2].c_str());
								if (infoDat[1] == "count") count = atoi(infoDat[2].c_str());
							}
						}
						((PlayerInfo*)(peer->data))->lastdropitem = idx;
						((PlayerInfo*)(peer->data))->lastdropitemcount = count;

						if (idx == -1) continue;
						if (itemDefs.size() < idx || idx < 0) continue;
						if (((PlayerInfo*)(peer->data))->lastdropitem == 18 || ((PlayerInfo*)(peer->data))->lastdropitem == 32) {
							GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You can't drop that."));
							ENetPacket* packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
							continue;
						}
						else {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wDrop " + itemDefs.at(idx).name + "``|left|" + std::to_string(idx) + "|\nadd_textbox|`oHow many to drop?|\nadd_text_input|dropitemcount|||3|\nend_dialog|dropdialog|Cancel|Ok|\n"));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;
							/*GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`#Drop Coming Soon!"));
							ENetPacket* packet = enet_packet_create(ps.data,
								ps.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete ps.data;
							continue;*/
						}
					}
					if (cch.find("text|") != std::string::npos) {
						if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
							sendConsoleMsg(peer, "`oTo prevent abuse, you `4must `obe `2registered `oin order to chat/command!");

							break;
						}
						if (((PlayerInfo*)(peer->data))->currentWorld == "EXIT") {
							sendConsoleMsg(peer, "You can't do that");
							break;
						}
						if (str.length() && str[0] == '/')
						{
							sendAction(peer, ((PlayerInfo*)(peer->data))->netID, str);
							if (str.find("/msg") != string::npos) {
								sendConsoleMsg(peer, "CP:_PL:0_OID:_CT:[MSG]_ `6" + str);
							}
							else if (str.find("/sb") != string::npos) {
								sendConsoleMsg(peer, "CP:_PL:0_OID:_CT:[SB]_ `6" + str);
							}
							else {
								sendConsoleMsg(peer, "`6" + str);
							}
						}
						else if (str.length() > 0)
						{
							bool canchat = true;
							bool unknown = true;
							if (((PlayerInfo*)(peer->data))->taped == false) {
								sendChatMessage(peer, ((PlayerInfo*)(peer->data))->netID, str);
							}
							else {
								for (char c : str)

									if (c < 0x18 || std::all_of(str.begin(), str.end(), isspace))
									{
										canchat = false;
									}
								if (canchat)
								{
									sendChatMessage(peer, ((PlayerInfo*)(peer->data))->netID, "mfmfmmfmfmff");

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Can't talk properly while you're duct-taped!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}

							}

						}
						PlayerInfo* pData = ((PlayerInfo*)(peer->data));
						bool exist = false;
						if (str == "/ghost")
						{
							exist = true;
							//if (getPlyersWorld(peer)->allowMod == false && world->owner != ((PlayerInfo*)(currentPeer->data))->rawName)





							if (getPlyersWorld(peer)->isCasino == true && ((PlayerInfo*)(peer->data))->rawName != world->owner) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `7You are not allowed to enable the /mod command in this world cause it is deactivated by owner."));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oModerator mode has been `2enabled`o! You can now walk through blocks!``"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								string text = "action|play_sfx\nfile|audio/secret.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length());
								memcpy(data + 4 + text.length(), &zero, 1);
								ENetPacket* packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p.data;
								delete data;
								((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
								sendState(peer);
							}
							/*PlayerMoving data;
							data.packetType = 0x14;
							data.characterState = 0x0; // animation
							data.x = 1000;
							data.y = 1;
							data.punchX = 0;
							data.punchY = 0;
							data.XSpeed = 300;
							data.YSpeed = 600;
							data.netID = ((PlayerInfo*)(peer->data))->netID;
							data.plantingTree = 0xFF;
							SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/
						}
						else if (str == "/save")
						{
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) < 444) break;
							saveAllWorlds();

						}
						else if (str.substr(0, 6) == "/mute ") {
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) < 444) break;
							if (str.substr(6, cch.length() - 6 - 1) == "mindpin") continue;
							if (str.substr(6, cch.length() - 6 - 1) == "senpai") continue;
							if (str.substr(6, cch.length() - 6 - 1) == "tyzies") continue;
							if (((PlayerInfo*)(peer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) continue;



							ENetPeer* currentPeer;

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `#** `$The Ancient Ones `ohave `4mute `2" + str.substr(6, cch.length() - 6 - 1) + " `#** `o(`4/rules `oto see the rules!)"));
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);


								if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) {
									if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;

									GamePacket ps3d = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oDuct tape has covered your mouth! (`$Duct Tape `omod added)"));
									ENetPacket* packet3d = enet_packet_create(ps3d.data,
										ps3d.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3d);

									GamePacket ps2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`0Warning from `4System`0: You've been `4MUTED `0from Private Server for 730 days"), "audio/hub_open.wav"), 0));
									ENetPacket* packet2 = enet_packet_create(ps2.data,
										ps2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									GamePacket ps3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oWarning from `4Admin`o: You've been `4duct-taped `ofrom Private Server"));
									ENetPacket* packet3 = enet_packet_create(ps3.data,
										ps3.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet3);
									((PlayerInfo*)(currentPeer->data))->isDuctaped = true;
									((PlayerInfo*)(currentPeer->data))->taped = true;
									sendState(currentPeer);
									if (((PlayerInfo*)(currentPeer->data))->isIn)
									{
										if (((PlayerInfo*)(currentPeer->data))->haveGrowId) {

											PlayerInfo* p = ((PlayerInfo*)(currentPeer->data));
											((PlayerInfo*)(currentPeer->data))->taped = true;
											string username = PlayerDB::getProperName(p->rawName);

											savejson(peer);
										}
									}

									// enet_peer_disconnect_later(currentPeer, 0);

								}

								enet_peer_send(currentPeer, 0, packet);

								//enet_host_flush(server);
							}
							delete p.data;
						}
						else if (str.substr(0, 6) == "/unmute ") {
						if (adminlevel(((PlayerInfo*)(peer->data))->rawName) < 444) break;
						if (str.substr(6, cch.length() - 6 - 1) == "mindpin") continue;
						if (str.substr(6, cch.length() - 6 - 1) == "senpai") continue;
						if (str.substr(6, cch.length() - 6 - 1) == "tyzies") continue;
						if (((PlayerInfo*)(peer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) continue;



						ENetPeer* currentPeer;

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `#** `$The Ancient Ones `ohave `2unmute `2" + str.substr(6, cch.length() - 6 - 1) + " `#** `o(`4/rules `oto see the rules!)"));
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);


							if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(6, cch.length() - 6 - 1)) {
								if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;

								GamePacket ps3d = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oNow you can talk again! (`$Duct Tape `omod removed)"));
								ENetPacket* packet3d = enet_packet_create(ps3d.data,
									ps3d.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet3d);

								GamePacket ps2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`0Warning from `4System`0: You've been `2UNMUTED `0from Private Server for 730 days"), "audio/hub_open.wav"), 0));
								ENetPacket* packet2 = enet_packet_create(ps2.data,
									ps2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet2);
								GamePacket ps3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oWarning from `4Admin`o: You've been `2Unmuted `ofrom Private Server"));
								ENetPacket* packet3 = enet_packet_create(ps3.data,
									ps3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet3);
								((PlayerInfo*)(currentPeer->data))->isDuctaped = false;
								((PlayerInfo*)(currentPeer->data))->taped = false;
								sendState(currentPeer);
								if (((PlayerInfo*)(currentPeer->data))->isIn)
								{
									if (((PlayerInfo*)(currentPeer->data))->haveGrowId) {

										PlayerInfo* p = ((PlayerInfo*)(currentPeer->data));
										((PlayerInfo*)(currentPeer->data))->taped = false;
										string username = PlayerDB::getProperName(p->rawName);

										savejson(peer);
									}
								}

								// enet_peer_disconnect_later(currentPeer, 0);

							}

							enet_peer_send(currentPeer, 0, packet);

							//enet_host_flush(server);
						}
						delete p.data;
						}
						else if (str.substr(0, 6) == "/mode ") // 9921116 blue fire mode // -529858286286 98156
						{
						string modestr = str.substr(6, cch.length() - 6 - 1);


						((PlayerInfo*)(peer->data))->characterState = atoi(modestr.c_str());
						sendState(peer);
						}
						else if (str.substr(0, 5) == "/spk ") {
						bool found = false;
						if (((PlayerInfo*)(peer->data))->adminLevel > 333) {

							string msg_info = str;

							size_t extra_space = msg_info.find("  ");
							if (extra_space != std::string::npos) {
								msg_info.replace(extra_space, 2, " ");
							}

							string delimiter = " ";
							size_t pos = 0;
							string pm_user;
							string pm_message;
							if ((pos = msg_info.find(delimiter)) != std::string::npos) {
								msg_info.erase(0, pos + delimiter.length());
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oPlease specify a `2player `oyou want your message to be delivered to."));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}

							if ((pos = msg_info.find(delimiter)) != std::string::npos) {
								pm_user = msg_info.substr(0, pos);
								msg_info.erase(0, pos + delimiter.length());
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oPlease enter your `2message`o."));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
							}

							pm_message = msg_info;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(pm_user)) {
									found = true;
									sendChatMessage(currentPeer, ((PlayerInfo*)(currentPeer->data))->netID, pm_message);
									sendConsoleMsg(peer, "`rPlayer `4" + ((PlayerInfo*)(currentPeer->data))->displayName + " `rhas just said `4" + pm_message);
								}

							}
							if (found == false)
							{
								GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `6Player " + PlayerDB::getProperName(pm_user) + " not found, remember to type all letters small."));
								ENetPacket* packet0 = enet_packet_create(p0.data,
									p0.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet0);
								delete p0.data;
							}
						}
								}
						else if (str.substr(0, 5) == "/pay ") {
							if (((PlayerInfo*)(peer->data))->haveGrowId) {
								if (((PlayerInfo*)(peer->data))->level > 10) {
									bool valid = true;
									string x = str.substr(5, cch.length() - 5 - 1);

									int pos = x.find(" ");
									string gemcount = x.substr(pos + 1);

									std::string addrWithMask(x);
									std::size_t pos1 = addrWithMask.find(" ");
									std::string playername = addrWithMask.substr(0, pos1);

									cout << "[!] /pay from " + ((PlayerInfo*)(peer->data))->rawName << " to: " + playername + " " + gemcount << endl;

									bool contains_non_alpha
										= !std::regex_match(gemcount, std::regex("^[0-9]+$"));

									for (char c : playername)
									{
										if (std::all_of(playername.begin(), playername.end(), isspace))
										{
											valid = false;
										}
									}

									if (contains_non_alpha || playername == "" || valid == false)
									{

										Player::OnConsoleMessage(peer, "`oInvalid syntax. Usage: /pay <name> <amount>``");
										break;

									}

									int gems = ((PlayerInfo*)(peer->data))->gem;
									if (atoi(gemcount.c_str()) > gems)
									{
										Player::OnConsoleMessage(peer, "`oNot enough `4gems`o.``");
										continue;
									}

									// peer variables
									bool found = false;
									// TODO GEM SYSTEM!!!
									int sgA1 = gems;
									int sgR1 = atoi(gemcount.c_str());
									int gemcalcminus = sgA1 - sgR1;
									// peer variables
									string pname = ((PlayerInfo*)(peer->data))->rawName;
									ENetPeer * currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;

										if (isHere(peer, currentPeer))
										{
											if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) {
												Player::OnConsoleMessage(peer, "`wPlayer does not have a GrowID!``");
												break;
											}
											if (PlayerDB::getProperName(playername) == ((PlayerInfo*)(currentPeer->data))->rawName) {
												string chkname = ((PlayerInfo*)(currentPeer->data))->rawName;

												if (chkname == PlayerDB::getProperName(((PlayerInfo*)(peer->data))->rawName))
												{
													break;
												}

												if (atoi(gemcount.c_str()) < 1)
												{
													found = true;
													Player::OnConsoleMessage(peer, "`oMaximum money amount is 1000000$`o.``");
													break;
												}

												if (atoi(gemcount.c_str()) > 1000000)
												{
													found = true;
													Player::OnConsoleMessage(peer, "`oMaximum money amount is 1000000$`o.``");
													break;

												}

												found = true;
												((PlayerInfo*)(peer->data))->gem = gemcalcminus;

												int sgA2 = ((PlayerInfo*)(currentPeer->data))->gem;
												int sgR2 = atoi(gemcount.c_str());
												int gemcalcplus = sgA2 + sgR2;
												((PlayerInfo*)(currentPeer->data))->gem = gemcalcplus;

												Player::OnSetBux(peer, gemcalcminus, 0);
												Player::OnSetBux(currentPeer, gemcalcplus, 0);
												time_t now = time(0);
												const char* dt = ctime(&now);
												tm* gmtm = gmtime(&now);
												dt = asctime(gmtm);
												std::string sendtime(dt);
												if (gmtm != NULL) {
												}
												else {
													break;
												}
												Player::OnConsoleMessage(peer, "`oSent `2" + gemcount + "$ `oto `$" + ((PlayerInfo*)(currentPeer->data))->displayName + ".``");
												((PlayerInfo*)(peer->data))->paid.push_back("[(`1" + sendtime + "`o): `oSent `2" + gemcount + "$ `oto `$" + ((PlayerInfo*)(currentPeer->data))->displayName + ".``");
												((PlayerInfo*)(currentPeer->data))->paid.push_back("(`1" + sendtime + "`o): `oReceived `2" + gemcount + "$ `ofrom `$" + ((PlayerInfo*)(peer->data))->displayName + ".``");
												Player::OnConsoleMessage(currentPeer, "`oReceived `2" + gemcount + "$ `ofrom `$" + ((PlayerInfo*)(peer->data))->displayName + ".``");
												savejson(peer);
												savejson(currentPeer);
												bool existx = std::experimental::filesystem::exists("players/" + pname + ".json");
												if (existx == false) {
													continue;
												}
												GamePacket p6 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `w[`cMOD LOGS `w- " + currentDateTime() + "`w] `2" + ((PlayerInfo*)(peer->data))->displayName + " (`$" + ((PlayerInfo*)(peer->data))->tankIDName + "`2) `wPayed `2" + ((PlayerInfo*)(currentPeer->data))->displayName + " `wfor `2" + gemcount + " `2gems``"));
												string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
												BYTE* data = new BYTE[5 + text.length()];
												BYTE zero = 0;
												int type = 3;
												memcpy(data, &type, 4);
												memcpy(data + 4, text.c_str(), text.length());
												memcpy(data + 4 + text.length(), &zero, 1);
												ENetPeer* currentPeer;
												for (currentPeer = server->peers;
													currentPeer < &server->peers[server->peerCount];
													++currentPeer)
												{
													if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
														continue;
													if (!((PlayerInfo*)(currentPeer->data))->radio)
														continue;
													if (((PlayerInfo*)(currentPeer->data))->adminLevel > 333) {
														ENetPacket* packet6 = enet_packet_create(p6.data,
															p6.len,
															ENET_PACKET_FLAG_RELIABLE);

														enet_peer_send(currentPeer, 0, packet6);




														ENetPacket* packet2 = enet_packet_create(data,
															5 + text.length(),
															ENET_PACKET_FLAG_RELIABLE);

														enet_peer_send(currentPeer, 0, packet2);

														//enet_host_flush(server);
													}
												}
											}
										}
									}
									if (found == false)
									{
										Player::OnConsoleMessage(peer, "`oPlayer not found!");
									}
								}
								else {
								sendConsoleMsg(peer, "You need atleast lvl 10+ to pay someone!");
								}

							}
						}
						else if (str == "/transaction") {
						string paiddone;

						string paidlist;

						for (std::vector<string>::const_iterator i = ((PlayerInfo*)(peer->data))->paid.begin(); i != ((PlayerInfo*)(peer->data))->paid.end(); ++i) {
							paiddone = *i;
							paidlist += paiddone + " ";
						}

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Transactions made this login: " + paidlist));
						ENetPacket * packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
							}
						else if (str.substr(0, 11) == "/givetoken ") {
							if (((PlayerInfo*)(peer->data))->adminLevel == 1337) {
								string msg_info = str;

								size_t extra_space = msg_info.find("  ");
								if (extra_space != std::string::npos) {
									msg_info.replace(extra_space, 2, " ");
								}

								string delimiter = " ";
								size_t pos = 0;
								string pm_user;
								string pm_message;
								if ((pos = msg_info.find(delimiter)) != std::string::npos) {
									msg_info.erase(0, pos + delimiter.length());
								}
								else {
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oPlease specify a `2player `oyou want to give level to him."));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;
								}

								if ((pos = msg_info.find(delimiter)) != std::string::npos) {
									pm_user = msg_info.substr(0, pos);
									msg_info.erase(0, pos + delimiter.length());
								}
								else {
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oPlease enter `2level `oamount."));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;
								}

								pm_message = msg_info;
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(pm_user)) {
										((PlayerInfo*)(peer->data))->wls = ((PlayerInfo*)(peer->data))->wls + atoi(pm_message.c_str());
										savejson(peer);
										((PlayerInfo*)(currentPeer->data))->lastMsger = ((PlayerInfo*)(peer->data))->rawName;
										((PlayerInfo*)(currentPeer->data))->lastMsgerTrue = ((PlayerInfo*)(currentPeer->data))->displayName;
										((PlayerInfo*)(currentPeer->data))->lastMsgWorld = ((PlayerInfo*)(peer->data))->currentWorld;
										GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oYou gave `2" + pm_message + " `oToken to player " + ((PlayerInfo*)(currentPeer->data))->displayName + "`4!"));
										ENetPacket* packet0 = enet_packet_create(p0.data,
											p0.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet0);
										delete p0.data;
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oYou Received `2" + pm_message + " `oGrowtale Token from `2" + ((PlayerInfo*)(peer->data))->displayName + "`4!"));
										string text = "action|play_sfx\nfile|audio/piano_nice.wav\ndelayMS|0\n";
										BYTE* data = new BYTE[5 + text.length()];
										BYTE zero = 0;
										int type = 3;
										memcpy(data, &type, 4);
										memcpy(data + 4, text.c_str(), text.length());
										memcpy(data + 4 + text.length(), &zero, 1);
										ENetPacket* packet2 = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet2);
										delete data;
										ENetPacket* packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										delete ps.data;

										break;
									}
								}
							}
						}
						else if (str.substr(0, 7) == "/level ") {
							if (((PlayerInfo*)(peer->data))->adminLevel == 1337) {
								((PlayerInfo*)(peer->data))->level = atoi(str.substr(7).c_str());
								int level = ((PlayerInfo*)(peer->data))->level;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Now your level are `2" + std::to_string(level) + "`0!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								savejson(peer);
							}
						}
						else if (str.substr(0, 7) == "/ipban ")
						{

						if (!canSB(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))break;
						if (str.substr(7, cch.length() - 7 - 1) == "") continue;
						if ((str.substr(7, cch.length() - 7 - 1) == "cmd") || (str.substr(7, cch.length() - 7 - 1) == "ttika") || (str.substr(7, cch.length() - 7 - 1) == "alpht")) continue;
						if (((PlayerInfo*)(peer->data))->rawName == str.substr(7, cch.length() - 7 - 1)) continue;



						cout << "[!] Server operator " << ((PlayerInfo*)(peer->data))->rawName << " has ipbanned " << str.substr(7, cch.length() - 7 - 1) << "." << endl;

						ENetPeer * currentPeer;

						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `#** `$The Ancient Ones `ohave `4ip-banned `2" + str.substr(7, cch.length() - 7 - 1) + " `#** `o(`4/rules `oto see the rules!)"));
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(7, cch.length() - 7 - 1)) {
								if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `#** `$The Ancient Ones `ohave used `#Ip-Ban `oon `2" + str.substr(7, cch.length() - 7 - 1) + "`o! `#**"));
								ENetPacket * packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet);

								GamePacket ps2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "`0Warning from `4System`0: You've been `4BANNED `0from Private Server for 730 days"), "audio/hub_open.wav"), 0));
								ENetPacket * packet2 = enet_packet_create(ps2.data,
									ps2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet2);
								GamePacket ps3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oWarning from `4System`o: You've been `4BANNED `ofrom Private Server for 730 days"));
								ENetPacket * packet3 = enet_packet_create(ps3.data,
									ps3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(currentPeer, 0, packet3);

								string ipban = "";
								std::ifstream ifs("ipban.json");
								ENetPeer * peer123 = currentPeer;
								string ip = std::to_string(peer123->address.host);
								if (ifs.is_open()) {

									json j3;
									ifs >> j3;
									ipban = j3["ip"];
									ipban = ipban.append("|" + ip + "|");
								}
								std::ofstream od("ipban.json");
								if (od.is_open()) {

								}

								std::ofstream o("ipban.json");
								if (!o.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}
								json j;

								j["ip"] = ipban;
								o << j << std::endl;
								delete ps.data;
								enet_peer_disconnect_later(currentPeer, 0);

							}

							enet_peer_send(currentPeer, 0, packet);

							//enet_host_flush(server);
						}
						delete p.data;
						}
						else if (str.substr(0, 11) == "/givelevel ") {
							if (((PlayerInfo*)(peer->data))->adminLevel == 1337) {
								string msg_info = str;

								size_t extra_space = msg_info.find("  ");
								if (extra_space != std::string::npos) {
									msg_info.replace(extra_space, 2, " ");
								}

								string delimiter = " ";
								size_t pos = 0;
								string pm_user;
								string pm_message;
								if ((pos = msg_info.find(delimiter)) != std::string::npos) {
									msg_info.erase(0, pos + delimiter.length());
								}
								else {
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oPlease specify a `2player `oyou want to give level to him."));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;
								}

								if ((pos = msg_info.find(delimiter)) != std::string::npos) {
									pm_user = msg_info.substr(0, pos);
									msg_info.erase(0, pos + delimiter.length());
								}
								else {
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oPlease enter `2level `oamount."));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;
								}

								pm_message = msg_info;
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(pm_user)) {
										((PlayerInfo*)(currentPeer->data))->level = atoi(pm_message.c_str());
										((PlayerInfo*)(currentPeer->data))->lastMsger = ((PlayerInfo*)(peer->data))->rawName;
										((PlayerInfo*)(currentPeer->data))->lastMsgerTrue = ((PlayerInfo*)(currentPeer->data))->displayName;
										((PlayerInfo*)(currentPeer->data))->lastMsgWorld = ((PlayerInfo*)(peer->data))->currentWorld;
										GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oYou gave level to player `2" + pm_message));
										ENetPacket* packet0 = enet_packet_create(p0.data,
											p0.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet0);
										delete p0.data;
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oYou got level from `2" + ((PlayerInfo*)(peer->data))->displayName + " `oNow you have `2" + pm_message + " `olevel!"));
										string text = "action|play_sfx\nfile|audio/piano_nice.wav\ndelayMS|0\n";
										BYTE* data = new BYTE[5 + text.length()];
										BYTE zero = 0;
										int type = 3;
										memcpy(data, &type, 4);
										memcpy(data + 4, text.c_str(), text.length());
										memcpy(data + 4 + text.length(), &zero, 1);
										ENetPacket* packet2 = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet2);
										delete data;
										ENetPacket* packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										delete ps.data;

										break;
									}
								}
							}
						}
						else if (str.substr(0, 8) == "/giveco ") {
							if (((PlayerInfo*)(peer->data))->rawName == "mindpin" || ((PlayerInfo*)(peer->data))->rawName == "fliqx" || ((PlayerInfo*)(peer->data))->rawName == "senpai" || ((PlayerInfo*)(peer->data))->rawName == "tyzies") {
								string name = str.substr(8, str.length());


								ENetPeer* currentPeer;


								bool found = false;


								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;


									string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;


									std::transform(name.begin(), name.end(), name.begin(), ::tolower);
									std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);


									if (name == name2) {
										GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "You received `9Co Creator"), "audio/hub_open.wav"), 0));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										((PlayerInfo*)(currentPeer->data))->adminLevel = 777;
										std::ifstream ifff("players/" + ((PlayerInfo*)(currentPeer->data))->rawName + ".json");


										if (ifff.fail()) {
											ifff.close();


										}
										if (ifff.is_open()) {
										}
										json j;
										ifff >> j; //load


										j["adminLevel"] = ((PlayerInfo*)(currentPeer->data))->adminLevel; //edit




										std::ofstream o("players/" + ((PlayerInfo*)(currentPeer->data))->rawName + ".json"); //save
										if (!o.is_open()) {
											cout << GetLastError() << endl;
											_getch();
										}

										o << j << std::endl;
										found = true;
										enet_peer_disconnect_later(currentPeer, 0);
									}
								}
								if (found) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `9You give mod to player " + name + "."));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Player not found!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
							}
						}

						else if (str.substr(0, 9) == "/givemod ") {
							if (((PlayerInfo*)(peer->data))->rawName == "mindpin" || ((PlayerInfo*)(peer->data))->rawName == "fliqx" || ((PlayerInfo*)(peer->data))->rawName == "senpai" || ((PlayerInfo*)(peer->data))->rawName == "tyzies") {
								string name = str.substr(9, str.length());


								ENetPeer* currentPeer;


								bool found = false;


								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;


									string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;


									std::transform(name.begin(), name.end(), name.begin(), ::tolower);
									std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);


									if (name == name2) {
										GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "You received `#MOD"), "audio/hub_open.wav"), 0));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										((PlayerInfo*)(currentPeer->data))->adminLevel = 444;
										std::ifstream ifff("players/" + ((PlayerInfo*)(currentPeer->data))->rawName + ".json");


										if (ifff.fail()) {
											ifff.close();


										}
										if (ifff.is_open()) {
										}
										json j;
										ifff >> j; //load


										j["adminLevel"] = ((PlayerInfo*)(currentPeer->data))->adminLevel; //edit




										std::ofstream o("players/" + ((PlayerInfo*)(currentPeer->data))->rawName + ".json"); //save
										if (!o.is_open()) {
											cout << GetLastError() << endl;
											_getch();
										}

										o << j << std::endl;
										found = true;
										enet_peer_disconnect_later(currentPeer, 0);
									}
								}
								if (found) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `9You give mod to player " + name + "."));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Player not found!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
							}
						}
						else if (str.substr(0, 9) == "/givevip ") {
							if (((PlayerInfo*)(peer->data))->rawName == "mindpin" || ((PlayerInfo*)(peer->data))->rawName == "fliqx" || ((PlayerInfo*)(peer->data))->rawName == "senpai" || ((PlayerInfo*)(peer->data))->rawName == "tyzies") {
								string name = str.substr(9, str.length());


								ENetPeer* currentPeer;


								bool found = false;


								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;


									string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;


									std::transform(name.begin(), name.end(), name.begin(), ::tolower);
									std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);


									if (name == name2) {
										GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "You received `cVIP"), "audio/hub_open.wav"), 0));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										((PlayerInfo*)(currentPeer->data))->adminLevel = 111;
										std::ifstream ifff("players/" + ((PlayerInfo*)(currentPeer->data))->rawName + ".json");


										if (ifff.fail()) {
											ifff.close();


										}
										if (ifff.is_open()) {
										}
										json j;
										ifff >> j; //load


										j["adminLevel"] = ((PlayerInfo*)(currentPeer->data))->adminLevel; //edit




										std::ofstream o("players/" + ((PlayerInfo*)(currentPeer->data))->rawName + ".json"); //save
										if (!o.is_open()) {
											cout << GetLastError() << endl;
											_getch();
										}

										o << j << std::endl;
										found = true;
										enet_peer_disconnect_later(currentPeer, 0);
									}
								}
								if (found) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `9You give vip to player " + name + "."));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Player not found!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
							}
						}
						else if (str.substr(0, 8) == "/demote ") {
							if (((PlayerInfo*)(peer->data))->rawName == "mindpin" || ((PlayerInfo*)(peer->data))->rawName == "fliqx" || ((PlayerInfo*)(peer->data))->rawName == "senpai" || ((PlayerInfo*)(peer->data))->rawName == "tyzies") {
								string name = str.substr(8, str.length());


								ENetPeer* currentPeer;


								bool found = false;


								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;


									string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;


									std::transform(name.begin(), name.end(), name.begin(), ::tolower);
									std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);


									if (name == name2) {
										GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "You has been `4DEMOTED`o!"), "audio/hub_open.wav"), 0));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										((PlayerInfo*)(currentPeer->data))->adminLevel = 0;
										std::ifstream ifff("players/" + ((PlayerInfo*)(currentPeer->data))->rawName + ".json");


										if (ifff.fail()) {
											ifff.close();


										}
										if (ifff.is_open()) {
										}
										json j;
										ifff >> j; //load


										j["adminLevel"] = ((PlayerInfo*)(currentPeer->data))->adminLevel; //edit




										std::ofstream o("players/" + ((PlayerInfo*)(currentPeer->data))->rawName + ".json"); //save
										if (!o.is_open()) {
											cout << GetLastError() << endl;
											_getch();
										}

										o << j << std::endl;
										found = true;
										enet_peer_disconnect_later(currentPeer, 0);
									}
								}
								if (found) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `9You give vip to player " + name + "."));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Player not found!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
							}
						}
						else if (str.substr(0, 11) == "/giveowner ") {
							if (((PlayerInfo*)(peer->data))->rawName == "mindpin" || ((PlayerInfo*)(peer->data))->rawName == "fliqx" || ((PlayerInfo*)(peer->data))->rawName == "senpai" || ((PlayerInfo*)(peer->data))->rawName == "tyzies") {
								string name = str.substr(11, str.length());


								ENetPeer* currentPeer;


								bool found = false;


								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;


									string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;


									std::transform(name.begin(), name.end(), name.begin(), ::tolower);
									std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);


									if (name == name2) {
										GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "You received `4Server Creator!"), "audio/hub_open.wav"), 0));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										((PlayerInfo*)(currentPeer->data))->adminLevel = 1337;
										std::ifstream ifff("players/" + ((PlayerInfo*)(currentPeer->data))->rawName + ".json");


										if (ifff.fail()) {
											ifff.close();


										}
										if (ifff.is_open()) {
										}
										json j;
										ifff >> j; //load


										j["adminLevel"] = ((PlayerInfo*)(currentPeer->data))->adminLevel; //edit




										std::ofstream o("players/" + ((PlayerInfo*)(currentPeer->data))->rawName + ".json"); //save
										if (!o.is_open()) {
											cout << GetLastError() << endl;
											_getch();
										}

										o << j << std::endl;
										found = true;
										enet_peer_disconnect_later(currentPeer, 0);
									}
								}
								if (found) {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `9You give owner to player " + name + "."));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Player not found!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);

									delete p.data;
								}
							}
						}
						
						
						else if (str == "/unequip")
						{
							((PlayerInfo*)(peer->data))->cloth_hair = 0;
							((PlayerInfo*)(peer->data))->cloth_shirt = 0;
							((PlayerInfo*)(peer->data))->cloth_pants = 0;
							((PlayerInfo*)(peer->data))->cloth_feet = 0;
							((PlayerInfo*)(peer->data))->cloth_face = 0;
							((PlayerInfo*)(peer->data))->cloth_hand = 0;
							((PlayerInfo*)(peer->data))->cloth_back = 5250;
							((PlayerInfo*)(peer->data))->cloth_mask = 0;
							((PlayerInfo*)(peer->data))->cloth_necklace = 0;
							((PlayerInfo*)(peer->data))->cloth_ances = 0;
							((PlayerInfo*)(peer->data))->peffect = 8421376;
							sendClothes(peer);
							sendState(peer);
							sendPuncheffect(peer);
						}
						else if (str.substr(0, 5) == "/find") {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFind item``|left|3802|\nadd_textbox|Enter a word below to find the item|\nadd_text_input|item|Item Name||30|\nend_dialog|findid|Cancel|Find the item!|\nadd_quick_exit|\n"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);

							//enet_host_flush(server);
							delete p.data;

						}
						else if (str == "/vips") {
							string x;

							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (((PlayerInfo*)(currentPeer->data))->adminLevel == 5) {
									x.append("`r" + ((PlayerInfo*)(currentPeer->data))->displayName + "``, ");
								}

							}
							x = x.substr(0, x.length() - 2);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `1VIPS Online: " + x));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
						}
						else if (str == "/mods") {
							string x;

							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;

								if (((PlayerInfo*)(currentPeer->data))->adminLevel > 333) {
									x.append(((PlayerInfo*)(currentPeer->data))->displayName + "``, ");

								}

							}
							x = x.substr(0, x.length() - 2);

							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oModerators Online: " + x));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
						}
						else if (str == "/help" || str == "/?") {
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] >> `5Supported Commands are``: /help, /?, /vhelp, /ghost (No Clip & Disable No Clip), /mods, /vips, /inventory, /item id, /color number, /who, /sb message, /radio, /weather <id>, /unequip, /find, /time, /msg, /clear, /pull, /kick, /r, /rgo, /go, /cry, /giveworld <player>, /news, /showlvl, /showgem, /howgay, /pay <player> <amount>, /rules, /time, /wl, /bluename (disable/enable BlueName for Level 50+), /clearchat, /clearinv, /doctor, /legend"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
						}
						else if (str.substr(0, 3) == "/a ") {
						ENetPeer * currentPeer;
						int imie = atoi(str.substr(3, cch.length() - 3 - 1).c_str());

						if (imie == 0) continue;
						if (imie == hasil) {
							resultnbr1 = 0;
							resultnbr2 = 0;
							hasil = 0;

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem + prize;
							prize = 0;

							GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket * packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							savejson(peer);
							string nama = ((PlayerInfo*)(peer->data))->displayName;
							ENetPeer * currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								sendConsole(currentPeer, "`w** `eGrowtale Private Server `1Daily Math: (party) Math Event Winner is `w" + nama + "`9!");
								sendSound(currentPeer, "pinata_lasso.wav");

							}
						}
						}
						/*else if (str == "/information") {
						PlayerInfo* info = ((PlayerInfo*)(peer->data));
						cout << info->tankIDName << endl;
						cout << info->tankIDPass << endl;
						cout << info->requestedName << endl;
						cout << info->f << endl;
						cout << info->protocol << endl;
						cout << info->gameVersion << endl;
						cout << info->fz << endl;
						cout << info->lmode << endl;
						cout << info->cbits << endl;
						cout << info->playerage << endl;
						cout << info->GDPR << endl;
						cout << info->hash2 << endl;
						cout << info->meta << endl;
						cout << info->fhash << endl;
						cout << info->rid << endl;
						cout << info->platformid << endl;
						cout << info->deviceversion << endl;
						cout << info->hash << endl;
						cout << info->mac << endl;
						cout << info->reconnect << endl;
						cout << info->wk << endl;
						cout << info->zf << endl;


						}*/
						else if (str == "/cry")
						{
							GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), ":'("), 0));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									enet_peer_send(currentPeer, 0, packet2);
								}
							}
							delete p2.data;
							continue;
						}
						else if (str == "/bluename") {

							if (((PlayerInfo*)(peer->data))->level < 50)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oYou need to be level `1125 `wto do that!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else {
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{
										GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(peer->data))->country + "|showGuild|maxLevel"));
										memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
										ENetPacket* packet2 = enet_packet_create(p2.data,
											p2.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet2);
										delete p2.data;
									}
								}
							}
						}
						else if (str == "/unbluename") {

							if (((PlayerInfo*)(peer->data))->level < 50)
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oYou need to be level `1125 `wto do that!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
							else {
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{
										GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnCountryState"), ((PlayerInfo*)(peer->data))->country + "|showGuild"));
										memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
										ENetPacket* packet2 = enet_packet_create(p2.data,
											p2.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet2);
										delete p2.data;
									}
								}
							}
						}
						else if (str.substr(0, 4) == "/me ")
						{
							if (((PlayerInfo*)(peer->data))->isDuctaped == false && ((PlayerInfo*)(peer->data))->haveGrowId == true)
							{
								string namer = ((PlayerInfo*)(peer->data))->displayName;
								GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`#<`w" + namer + " `#" + str.substr(3, cch.length() - 3 - 1).c_str() + "`5>"), 0));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `w<" + namer + " `#" + str.substr(3, cch.length() - 3 - 1).c_str() + "`w>"));
								ENetPacket* packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{
										enet_peer_send(currentPeer, 0, packet2);
										enet_peer_send(currentPeer, 0, packet3);
									}
								}
								delete p2.data;
								delete p3.data;
								continue;
							}
						}
						else if (str == "/news") {
							sendGazette(peer);
						}
						else if (str == "/clear") {
							if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFast world clear service|left|6768|\nadd_spacer|small|\nadd_label|small|`6This option will clear your world instantly|left|\nadd_label|small| `7You will be charged `45.000 gems|left|\nadd_spacer|small|\nadd_button|clearworld|`wClear my world!|\nadd_spacer|small|\nend_dialog|dialogend|Nevermind||\n"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								//enet_host_flush(server);
								delete p.data;
							}
						}
						else if (str == "/clearchat") {
							GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] \n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"));
							ENetPacket* packet0 = enet_packet_create(p0.data,
								p0.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet0);
							delete p0.data;
							GamePacket p02 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wCleared chat!"));
							ENetPacket* packet02 = enet_packet_create(p02.data,
								p02.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet02);
							delete p02.data;
						}
						else if (str == "/time") {
							sendTime(peer);
						}
						else if (str == "/howgay") {
							ENetPeer* currentPeer;
							int val = rand() % 100;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer))
								{
									GamePacket p2 = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), ((PlayerInfo*)(peer->data))->netID), "`w" + ((PlayerInfo*)(peer->data))->displayName + " `oare `2" + std::to_string(val) + "% `wgay!"), 0));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet2);
									delete p2.data;
									GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), ((PlayerInfo*)(peer->data))->displayName + " `ware `2%" + std::to_string(val) + " `wgay!"));
									ENetPacket* packet0 = enet_packet_create(p0.data,
										p0.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet0);
									delete p0.data;
								}
							}
						}
						else if (str == "/uba") {
							if (((PlayerInfo*)(peer->data))->haveGrowId && ((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner || ((PlayerInfo*)(peer->data))->adminLevel > 333) {
								namespace fs = std::experimental::filesystem;
								fs::remove_all("worldbans/" + getPlyersWorld(peer)->name);

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oYou unbanned everyone from the world!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						else if (str == "/vhelp") {
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) >= 111) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] >> `$THE RECLUSE Commands are`o: /nick <nickname>, /vsb <text> [VIP-SB] /warp <world name>, /search <player>, flag <id>,  /v <text> [VIP-CHAT], /copyset <user>, /invis, /country <country flag id>"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
						}
						else if (str == "/mhelp") {
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) >= 444) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] >> `#THE AMBITIOUS Commands are`o: /nick <nickname>, /vsb <text> [VIP-SB] /warp <world name>, /search <player>, flag <id>,  /v <text> [VIP-CHAT], /copyset <user>, /invis, /country <country flag id>, /msb <text> [MOD-SB], /gameban <name>, /mute <name>"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
						}
						else if (str == "/ohelp") {
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) >= 1337) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] >> `cTHE JUDGE Commands are`o: /nick <nickname>, /osb <text> [THE JUDGE-SB] /warp <world name>, /warpto <name>, /search <player>, /invis, /vis , /country <country flag id>, /gameban <name>, /mute <name>, /curse <name>, /spk <text> , /give <Gems Amount>, /givetoken <Token amount>, /givevip, /givemod, /giveco ( mindpin , Senpai, tyzies ONLY), /giveowner ( mindpin, Senpai, tyzies ONLY), /giveowner ( mindpin, Senpai, tyzies ONLY ), /ban (name) (time)"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
						}
						
						else if (str == "/cohelp") {
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) >= 777) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] >> `eServer-Co-Creator Commands are`o: /nick <nickname>, /cob <text>, /warp <world name>, /warpto <name>, /search <player>, /invis, /vis , /country <country flag id>, /gameban <name>, /mute <name>, /curse <name>, /spk <text> , /ban (name) (time)"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
							}
						}
						
						else if (str == "/gtfxcold") {
							GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetBetaMode"), 1));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						else if (str.substr(0, 5) == "/ban ") {
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) >= 444) {
								sendConsoleMsg(peer, "sorry this command is disabled for a while.");
							}
						}
						else if (str.substr(0, 9) == "/copyset ") {
							if (((PlayerInfo*)(peer->data))->adminLevel >= 111) {

								string name = str.substr(9, cch.length() - 9 - 1);
								int netID = ((PlayerInfo*)(peer->data))->netID;
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;

									if (((PlayerInfo*)(currentPeer->data))->rawName == name || ((PlayerInfo*)(currentPeer->data))->tankIDName == name) {
										((PlayerInfo*)(peer->data))->cloth_hair = ((PlayerInfo*)(currentPeer->data))->cloth_hair;
										((PlayerInfo*)(peer->data))->cloth_shirt = ((PlayerInfo*)(currentPeer->data))->cloth_shirt;
										((PlayerInfo*)(peer->data))->cloth_pants = ((PlayerInfo*)(currentPeer->data))->cloth_pants;
										((PlayerInfo*)(peer->data))->cloth_feet = ((PlayerInfo*)(currentPeer->data))->cloth_feet;
										((PlayerInfo*)(peer->data))->cloth_face = ((PlayerInfo*)(currentPeer->data))->cloth_face;
										((PlayerInfo*)(peer->data))->cloth_hand = ((PlayerInfo*)(currentPeer->data))->cloth_hand;
										((PlayerInfo*)(peer->data))->cloth_back = ((PlayerInfo*)(currentPeer->data))->cloth_back;
										((PlayerInfo*)(peer->data))->cloth_mask = ((PlayerInfo*)(currentPeer->data))->cloth_mask;
										((PlayerInfo*)(peer->data))->cloth_necklace = ((PlayerInfo*)(currentPeer->data))->cloth_necklace;
										((PlayerInfo*)(peer->data))->skinColor = ((PlayerInfo*)(currentPeer->data))->skinColor;
										sendClothes(peer);

										GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`^You `9Copied `@Player `4" + ((PlayerInfo*)(currentPeer->data))->displayName + "`^ Clothes!"));
										string text = "action|play_sfx\nfile|audio/change_clothes.wav\ndelayMS|0\n";
										BYTE* data = new BYTE[5 + text.length()];
										BYTE zero = 0;
										int type = 3;
										memcpy(data, &type, 4);
										memcpy(data + 4, text.c_str(), text.length());
										memcpy(data + 4 + text.length(), &zero, 1);

										ENetPacket* packet1 = enet_packet_create(p1.data,
											p1.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet1);

										ENetPacket* packet2 = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packet2);

										delete p1.data;
										delete data;
									}
								}
							}
						}
						else if (str.substr(0, 8) == "/warpto ") {
						if (((PlayerInfo*)(peer->data))->adminLevel > 333) {
							string name = str.substr(8, str.length());


							ENetPeer* currentPeer;


							bool found = false;


							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;


								string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;


								std::transform(name.begin(), name.end(), name.begin(), ::tolower);
								std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);


								if (name == name2) {
									if (((PlayerInfo*)(currentPeer->data))->currentWorld == "EXIT")
									{
										//std::this_thread::sleep_for(std::chrono::milliseconds(200));
									}
									else
									{
										sendPlayerToPlayer(peer, currentPeer);
										found = true;
									}

								}
							}
							if (found) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Warping to player."));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete p.data;
							}
							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Player not found or is currently in EXIT."));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								delete p.data;
							}
						}


						}
						else if (str.substr(0, 8) == "/summon ") {
						if (((PlayerInfo*)(peer->data))->adminLevel > 333) {
							if ((str.substr(8, cch.length() - 8 - 1) == "mindpin") || (str.substr(8, cch.length() - 8 - 1) == "senpai")) continue;
							if ((str.substr(8, cch.length() - 8 - 1) == "fliqx") || (str.substr(8, cch.length() - 8 - 1) == "tyzies")) continue;
							string name = str.substr(8, str.length());


							ENetPeer* currentPeer;


							bool found = false;


							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;


								string name2 = ((PlayerInfo*)(currentPeer->data))->rawName;


								std::transform(name.begin(), name.end(), name.begin(), ::tolower);
								std::transform(name2.begin(), name2.end(), name2.begin(), ::tolower);


								if (name == name2) {
									GamePacket pox = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "You were summoned by a mod."));
									ENetPacket* packetpox = enet_packet_create(pox.data,
										pox.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packetpox);
									updateAllClothes(currentPeer);
									sendClothes(currentPeer);
									sendPlayerToPlayer(currentPeer, peer);
									found = true;
								}


							}
							if (found) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `9Summoning " + name));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Player not found!"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
							}
						}


						}
						else if (str.substr(0, 9) == "/gameban ")
						{
							if (((PlayerInfo*)(peer->data))->adminLevel >= 444) {
								if ((str.substr(9, cch.length() - 9 - 1) == "mindpin") || (str.substr(9, cch.length() - 9 - 1) == "senpai")) continue;
								if ((str.substr(9, cch.length() - 9 - 1) == "fliqx") || (str.substr(9, cch.length() - 9 - 1) == "tyzies")) continue;
								ENetPeer* currentPeer;
								string real = "";
								string imie = str.substr(9, cch.length() - 9 - 1);
								toUpperCase(imie);
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									string lolzzz = ((PlayerInfo*)(currentPeer->data))->rawName;
									toUpperCase(lolzzz);
									if (lolzzz == imie) {

										string nick = ((PlayerInfo*)(currentPeer->data))->rawName;
										real = nick;

										sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
										GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/atomic_button.rttex"), "Warning From `4Admin :`w You've been`4 BANNED`w from Growtopia"), "audio/hub_open.wav"), 0));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);
										delete p.data;
										enet_peer_disconnect_later(currentPeer, 0);

										GamePacket ban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `#**`w" + ((PlayerInfo*)(peer->data))->rawName + "`o has `4Banned`o player`w " + imie + "`#**"));
										ENetPacket* packetba = enet_packet_create(ban.data,
											ban.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packetba);
										delete ban.data;

										bannedlist.push_back(((PlayerInfo*)(currentPeer->data))->tankIDName);
										enet_peer_disconnect_later(currentPeer, 0);
									}
									else {
										bannedlist.push_back(imie);

									}

								}
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									GamePacket pban = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `#**`w" + ((PlayerInfo*)(peer->data))->rawName + "`o has `4Banned`o player`w " + imie + "`#**"));
									ENetPacket* packet45 = enet_packet_create(pban.data, pban.len, ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet45);
									delete pban.data;
								}

							}
						}
						else if (str.substr(0, 5) == "/msg ") {
							bool found = false;


							string msg_info = str;

							size_t extra_space = msg_info.find("  ");
							if (extra_space != std::string::npos) {
								msg_info.replace(extra_space, 2, " ");
							}

							string delimiter = " ";
							size_t pos = 0;
							string pm_user;
							string pm_message;
							if ((pos = msg_info.find(delimiter)) != std::string::npos) {
								msg_info.erase(0, pos + delimiter.length());
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oPlease specify a `2player `oyou want your message to be delivered to."));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
								break;
							}

							if ((pos = msg_info.find(delimiter)) != std::string::npos) {
								pm_user = msg_info.substr(0, pos);
								msg_info.erase(0, pos + delimiter.length());
							}
							else {
								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oPlease enter your `2message`o."));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete ps.data;
								break;
							}

							pm_message = msg_info;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(pm_user)) {

									((PlayerInfo*)(currentPeer->data))->lastMsger = ((PlayerInfo*)(peer->data))->rawName;
									((PlayerInfo*)(currentPeer->data))->lastMsgerTrue = ((PlayerInfo*)(currentPeer->data))->displayName;
									((PlayerInfo*)(currentPeer->data))->lastMsgWorld = ((PlayerInfo*)(peer->data))->currentWorld;

									//sendConsoleMsg(peer, "`6" + str);
									GamePacket p0;
									if (((PlayerInfo*)(currentPeer->data))->adminLevel == 1337) {
										p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `6>> (Sent to `$" + ((PlayerInfo*)(currentPeer->data))->tankIDName + "`6) `o(`4Note: ``Message a mod `4ONLY ONCE `oabout an issue. Mods dont fix scams or replace gems, they punish players who break the `5/rules`o. For issues related to account recovery or purchasing, send message to creators on discord.)"));
									}
									else {
										p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `6>> (Sent to `$" + ((PlayerInfo*)(currentPeer->data))->tankIDName + "`6)"));
									}
									ENetPacket* packet0 = enet_packet_create(p0.data,
										p0.len,
										ENET_PACKET_FLAG_RELIABLE);
									GamePacket p10 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `6>> (Sent to `$" + ((PlayerInfo*)(currentPeer->data))->tankIDName + "`6) `o(`4Note: ``Message a mod `4ONLY ONCE `oabout an issue. Mods dont fix scams or replace gems, they punish players who break the `5/rules`o. For issues related to account recovery or purchasing, send message to creators on discord.)"));
									ENetPacket* packet10 = enet_packet_create(p10.data,
										p10.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet0);
									delete p0.data;
									delete p10.data;
									found = true;
									GamePacket ps;
									if (((PlayerInfo*)(currentPeer->data))->adminLevel == 1337) {
										ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:0_PL:2_OID:_CT:[MSG]_ `c>> from (`w" + ((PlayerInfo*)(peer->data))->displayName + "`c) in [`4<HIDDEN>`c] > `$" + pm_message));
									}
									else {
										ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:0_PL:2_OID:_CT:[MSG]_ `c>> from (`w" + ((PlayerInfo*)(peer->data))->displayName + "`c) in [`$" + ((PlayerInfo*)(peer->data))->currentWorld + "`c] > `$" + pm_message));
									}
									string text = "action|play_sfx\nfile|audio/pay_time.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);
									ENetPacket* packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete data;
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete ps.data;
									break;
								}

							}
							if (found == false)
							{
								GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `6Player " + PlayerDB::getProperName(pm_user) + " not found, remember to type all letters small."));
								ENetPacket* packet0 = enet_packet_create(p0.data,
									p0.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet0);
								delete p0.data;
							}
						}
						else if (str == "/rules") {
							//cout << "[!] /rules from " << ((PlayerInfo*)(peer->data))->displayName << endl;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wHelp & Rules``|left|18|\n\nadd_spacer|small|\nadd_label|small|`wTo keep this community,We've got some rules to follow it:|left|1432|\nadd_label_with_icon|small|`wKeep your password secret.sharing your password will result in stolen world.|left|1432|\nadd_label_with_icon|small|`0Be civil. Bullying, racism,excessive profanity,sexual content and abuse behavior is not allowed|left|1432|\nadd_label_with_icon|small|`wUsing 1 hit ingame is illegal.Except you are using Rayman + sorrow.|left|1432|\nadd_label_with_icon|small|`wTrying to get punishment or asking for punishment can earn you a worse punishment.|left|1432|\nadd_label_with_icon|small|`wDon't lie about mods or fake official Growtale system messages.``|left|1432|\nadd_label_with_icon|small|`wSelling gems for outside server items is illegal!|left|1432|\nadd_label_with_icon|small|`wDo not sb about a rude stuff.|left|1432|\nadd_label_with_icon|small|`0Do not war sb.|left|1432|\nadd_label_with_icon|small|`0Any advertising in any manner will lead to a ban or mute|left|1432|\nadd_label_with_icon|small|`0A Staff insult or other players can lead to a demotion in rank or mute or ban or curse.|left|1432|\nadd_label_with_icon|small|`0Any mention of selling your account will result in your account being blocked.|left|1432|\nadd_label_with_icon|small|`w@Moderators are here to enforce the rules. Abusing, spamming or harassing mods will have consequences.|left|1432|\nadd_label_with_icon|small|`w/ban, /mute, /curse, /warn without proofs may result in demotion .|left|1432|\nadd_label|small|`0Thank You!|left|21|\nadd_label|small|~`e@Growtale Support|left|32|\nadd_button|chc0|`0I accept these Rules.|"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							//enet_host_flush(server);
							delete p.data;
						}
						else if (str.substr(0, 5) == "/spk ") {
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) > 111) {
								sendConsoleMsg(peer, "sorry this command is disabled for a while.");
							}
						}
						else if (str.substr(0, 3) == "/r ") {
							if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
								GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oTo prevent abuse, you `4must `obe `2registered `oin order to use this command!"));
								ENetPacket* packet0 = enet_packet_create(p0.data,
									p0.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet0);
								delete p0.data;
								continue;
							}


							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == ((PlayerInfo*)(peer->data))->lastMsger) {

									((PlayerInfo*)(currentPeer->data))->lastMsger = ((PlayerInfo*)(peer->data))->rawName;
									GamePacket p0 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `6>> (Sent to `2" + ((PlayerInfo*)(peer->data))->lastMsger + "`6)"));
									ENetPacket* packet0 = enet_packet_create(p0.data,
										p0.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet0);
									delete p0.data;
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `6>> Private msg from `2" + ((PlayerInfo*)(peer->data))->displayName + "`6 (`$in " + ((PlayerInfo*)(peer->data))->currentWorld + "`6) : " + str.substr(3, cch.length() - 3 - 1) + "`o"));
									string text = "action|play_sfx\nfile|audio/pay_time.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);
									ENetPacket* packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);
									delete data;
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packet);
									delete ps.data;
									break;
								}
							}
						}
						/*else if (str.substr(0, 7) == "/trade ") {
						bool found = false;
						string Name = str.substr(7, cch.length() - 7 - 1);
						if (((PlayerInfo*)(peer->data))->rawName == Name) {
							sendConsoleMsg(peer, "You can't trade yourself!");
							continue;
						}
						else if (((PlayerInfo*)(peer->data))->tradeSomeone) {
							sendConsoleMsg(peer, "Cancel current trade before trade other");
							continue;
						}

						if (((PlayerInfo*)(peer->data))->trdStarter == Name) {

							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (isHere(peer, currentPeer)) {
									if (((PlayerInfo*)(peer->data))->trdStarter == ((PlayerInfo*)(currentPeer->data))->rawName) {
										GamePacket pt1 = packetEnd(appendInt(appendString(appendString(createPacket(), "OnStartTrade"), ((PlayerInfo*)(currentPeer->data))->rawName), ((PlayerInfo*)(currentPeer->data))->netID));
										ENetPacket* packetw = enet_packet_create(pt1.data,
											pt1.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packetw);
										delete pt1.data;
										GamePacket pty = packetEnd(appendInt(appendString(appendString(createPacket(), "OnStartTrade"), ((PlayerInfo*)(peer->data))->rawName), ((PlayerInfo*)(peer->data))->netID));
										ENetPacket* packety = enet_packet_create(pty.data,
											pty.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packety);
										delete pty.data;
									}
								}
							}
							continue;
						}
						ENetPeer* currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (isHere(peer, currentPeer)) {
								if (((PlayerInfo*)(currentPeer->data))->rawName == Name) {
									found = true;
									if (((PlayerInfo*)(currentPeer->data))->tradeSomeone) {
										sendConsoleMsg(peer, "That player already trade with someone else");
										continue;
									}


									GamePacket pt1 = packetEnd(appendInt(appendString(appendString(createPacket(), "OnStartTrade"), ((PlayerInfo*)(currentPeer->data))->rawName), ((PlayerInfo*)(currentPeer->data))->netID));
									ENetPacket* packetw = enet_packet_create(pt1.data,
										pt1.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packetw);
									delete pt1.data;
									GamePacket pty = packetEnd(appendInt(appendString(appendString(createPacket(), "OnStartTrade"), ((PlayerInfo*)(peer->data))->rawName), ((PlayerInfo*)(peer->data))->netID));
									ENetPacket* packety = enet_packet_create(pty.data,
										pty.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(currentPeer, 0, packety);
									delete pty.data;

								}

							}
						}
						if (!found) {
							sendConsoleMsg(peer, "The player no found ");
						}
						}*/
						else if (str.substr(0, 2) == "/ ") {
							if (((PlayerInfo*)(peer->data))->adminLevel > 111) {
								string name = ((PlayerInfo*)(peer->data))->displayName;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `#[MOD-CHAT] `2" + ((PlayerInfo*)(peer->data))->tankIDName + "`r(" + ((PlayerInfo*)(peer->data))->displayName + "`r): `6" + str.substr(2, cch.length() - 2 - 1)));
								string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length());
								memcpy(data + 4 + text.length(), &zero, 1);
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (!((PlayerInfo*)(currentPeer->data))->radio)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->adminLevel > 333) {
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet);




										ENetPacket* packet2 = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet2);

										//enet_host_flush(server);
									}
								}
								delete data;
								delete p.data;
							}
						}
						else if (str.substr(0, 3) == "/v ") {
							if (((PlayerInfo*)(peer->data))->adminLevel >= 111) {
								using namespace std::chrono;
								if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
								{
									((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
								}
								else {
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Wait a minute before using the Vip Chat command again!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet);
									delete p.data;
									//enet_host_flush(server);
									continue;
								}

								string name = ((PlayerInfo*)(peer->data))->displayName;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `3[VIP CHAT] `2" + ((PlayerInfo*)(peer->data))->tankIDName + "`3(" + ((PlayerInfo*)(peer->data))->displayName + "`3): `6" + str.substr(3, cch.length() - 3 - 1)));
								string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length());
								memcpy(data + 4 + text.length(), &zero, 1);
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (!((PlayerInfo*)(currentPeer->data))->radio)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->adminLevel > 2) {
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet);




										ENetPacket* packet2 = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet2);

										//enet_host_flush(server);
									}
								}
								delete data;
								delete p.data;
							}
						}
						else if (str == "/nuke") {
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) > 333) {

								WorldInfo* world = getPlyersWorld(peer);
								if (world->isNuked) {
									world->isNuked = false;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `2You have un-nuked the world"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
								}
								else {
									world->isNuked = true;
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4You have nuked the world!"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);


									ENetPeer* currentPeer;


									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;


										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4" + world->name + " has been nuked from orbit. `o>> It's the only way to be sure. Play safe, everybody!"));
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(currentPeer, 0, packet);

										string text = "action|play_sfx\nfile|audio/bigboom.wav\ndelayMS|0\n";
										BYTE* data = new BYTE[5 + text.length()];
										BYTE zero = 0;
										int type = 3;
										memcpy(data, &type, 4);
										memcpy(data + 4, text.c_str(), text.length());
										memcpy(data + 4 + text.length(), &zero, 1);


										ENetPacket* packetnuk = enet_packet_create(data,
											5 + text.length(),
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packetnuk);


										if (isHere(peer, currentPeer)) {
											if (adminlevel(((PlayerInfo*)(currentPeer->data))->rawName) < 334) {

												//((PlayerInfo*)(currentPeer->data))->currentWorld = "EXIT";
												sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
												sendWorldOffers(currentPeer);


												((PlayerInfo*)(currentPeer->data))->currentWorld = "EXIT";
											}

										}
									}
								}
							}





						}
						else if (str == "/casino") {
							if (((PlayerInfo*)(peer->data))->haveGrowId && ((PlayerInfo*)(peer->data))->rawName == getPlyersWorld(peer)->owner || ((PlayerInfo*)(peer->data))->adminLevel > 333) {
								string act = ((PlayerInfo*)(peer->data))->currentWorld;
								bool casin = world->isCasino == true;
								string accessname = "";

								for (std::vector<string>::const_iterator i = world->acclist.begin(); i != world->acclist.end(); ++i) {
									accessname = *i;
								}
								if (casin)
								{

									world->isCasino = false;
									ENetPeer * currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer))
										{
											sendConsoleMsg(currentPeer, "World owner has been `2ENABLED `ono clipping in this world`o!");

										}
									}
								}
								else
								{

									world->isCasino = true;

									ENetPeer * currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer))
										{
											sendConsoleMsg(currentPeer, "World owner has been `4DISABLED `ono clipping in this world`o!");
											if (((PlayerInfo*)(currentPeer->data))->rawName == world->owner || ((PlayerInfo*)(currentPeer->data))->adminLevel > 1119 || ((PlayerInfo*)(currentPeer->data))->rawName == accessname)
											{

											}
											else
											{
												((PlayerInfo*)(currentPeer->data))->isGhost = false;
												sendState(currentPeer);
											}


										}
									}
								}
							}
						}
						else if (str.substr(0, 6) == "/nick ") {
						if (((PlayerInfo*)(peer->data))->adminLevel >= 111) {
							string name2 = "`w`w" + str.substr(6, cch.length() - 6 - 1);
							((PlayerInfo*)(peer->data))->msgName = PlayerDB::getProperName(str.substr(6, cch.length() - 6 - 1));

							string lognickname = str.substr(6, cch.length() - 6 - 1);
							if (name2.length() < 5 && getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) != 999)
							{
								GamePacket psa = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `9VIP's`w cannot nick to nothing."));
								ENetPacket* packetsa = enet_packet_create(psa.data,
									psa.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetsa);
								delete psa.data;
							}
							else
							{

								cout << ((PlayerInfo*)(peer->data))->rawName << " nicked into " << lognickname << endl;




								((PlayerInfo*)(peer->data))->displayName = str.substr(6, cch.length() - 6 - 1);
								((PlayerInfo*)(peer->data))->country = "id";
								((PlayerInfo*)(peer->data))->isNicked = true;




								GamePacket p7 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), name2));
								memcpy(p7.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor

								((PlayerInfo*)(peer->data))->displayName = name2;
								ENetPacket* packet7 = enet_packet_create(p7.data,
									p7.len,
									ENET_PACKET_FLAG_RELIABLE);



								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{
										enet_peer_send(currentPeer, 0, packet7);
									}
								}
								delete p7.data;

								GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Your nickname has been changed to `2" + str.substr(6, cch.length() - 6 - 1) + "`o! Type /nick (only /nick, to get default name back!)"));
								ENetPacket* packet = enet_packet_create(ps.data,
									ps.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete ps.data;
								string name = ((PlayerInfo*)(peer->data))->displayName;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `w[`cMOD LOGS `w- " + currentDateTime() + "`w]  `6" + ((PlayerInfo*)(peer->data))->tankIDName + "`r(`6" + ((PlayerInfo*)(peer->data))->displayName + "`r) `4Changing `2Nickname `4To `w" + str.substr(6, cch.length() - 6 - 1)));

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (!((PlayerInfo*)(currentPeer->data))->radio)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->adminLevel >= 444) {
										ENetPacket* packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(currentPeer, 0, packet);

										//enet_host_flush(server);
									}
								}
								delete p.data;
							}
						}
						}
						else if (str == "/nick")
											{
											if (getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 999 || getAdminLevel(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass) == 666) {
												string name2;
												string namemsg = ((PlayerInfo*)(peer->data))->rawName;
												((PlayerInfo*)(peer->data))->isNicked = false;
												if (((PlayerInfo*)(peer->data))->adminLevel == 1337)
												{
													name2 = "`c@" + ((PlayerInfo*)(peer->data))->tankIDName;
													((PlayerInfo*)(event.peer->data))->country = "rt";
												}
												else if (((PlayerInfo*)(peer->data))->adminLevel == 999)
												{
													name2 = "`6@" + ((PlayerInfo*)(peer->data))->tankIDName;
													((PlayerInfo*)(event.peer->data))->country = "rt";
												}
												else if (((PlayerInfo*)(peer->data))->adminLevel == 777)
												{
													name2 = "`4@" + ((PlayerInfo*)(peer->data))->tankIDName;
													((PlayerInfo*)(event.peer->data))->country = "rt";
												}
												else if (((PlayerInfo*)(peer->data))->adminLevel == 666)
												{
													name2 = "`w[`4Administrator`w] " + ((PlayerInfo*)(peer->data))->tankIDName;
													((PlayerInfo*)(event.peer->data))->country = "rt";
												}
												else if (((PlayerInfo*)(peer->data))->adminLevel == 444)
												{
													name2 = "`#@" + ((PlayerInfo*)(peer->data))->tankIDName;
													((PlayerInfo*)(event.peer->data))->country = "../";
												}
												else if (((PlayerInfo*)(peer->data))->adminLevel == 111)
												{
													name2 = "`$@" + ((PlayerInfo*)(peer->data))->tankIDName;

												}

												((PlayerInfo*)(peer->data))->displayName = name2;
												((PlayerInfo*)(peer->data))->msgName = namemsg;
												GamePacket p7 = packetEnd(appendString(appendString(createPacket(), "OnNameChanged"), name2));
												memcpy(p7.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4); // ffloor

												((PlayerInfo*)(peer->data))->displayName = name2;
												ENetPacket* packet7 = enet_packet_create(p7.data,
													p7.len,
													ENET_PACKET_FLAG_RELIABLE);



												ENetPeer* currentPeer;
												for (currentPeer = server->peers;
													currentPeer < &server->peers[server->peerCount];
													++currentPeer)
												{
													if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
														continue;
													if (isHere(peer, currentPeer))
													{
														enet_peer_send(currentPeer, 0, packet7);
													}
												}
												delete p7.data;

												GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oYour nickname has been reverted!"));
												ENetPacket* packet = enet_packet_create(ps.data,
													ps.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(peer, 0, packet);
												delete ps.data;
											}
											}
						else if (str.substr(0, 6) == "/give ")
						{
						if (((PlayerInfo*)(peer->data))->adminLevel == 1337) {
							int gems = atoi(str.substr(6).c_str());;
							((PlayerInfo*)(peer->data))->gem = atoi(str.substr(6).c_str());
							GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							continue;





						}
						}
						else if (str.substr(0, 9) == "/weather ") {
							if (world->name != "ADMIN") {
								if (world->owner != "") {
									if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))

									{
										ENetPeer* currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{
												GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oPlayer `2" + ((PlayerInfo*)(peer->data))->displayName + "`o has just changed the world's weather!"));
												ENetPacket* packet1 = enet_packet_create(p1.data,
													p1.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet1);
												delete p1.data;

												GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "OnSetCurrentWeather"), atoi(str.substr(9).c_str())));
												ENetPacket* packet2 = enet_packet_create(p2.data,
													p2.len,
													ENET_PACKET_FLAG_RELIABLE);

												enet_peer_send(currentPeer, 0, packet2);
												delete p2.data;
												world->weather = atoi(str.substr(9).c_str());
												continue; /*CODE UPDATE /WEATHER FOR EVERYONE!*/
											}
										}
									}
								}
							}
						}
						else if (str.substr(0, 11) == "/giveworld ") {
							//owner
							if (world->name != "ADMIN") {
								if (world->owner != "") {
									if (((PlayerInfo*)(peer->data))->rawName == world->owner || ((PlayerInfo*)(peer->data))->adminLevel == 1337)

									{
										ENetPeer* currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{

												string name = str.substr(11, cch.length() - 11 - 1);
												if (((PlayerInfo*)(currentPeer->data))->rawName == str.substr(11, cch.length() - 11 - 1)) {
													if (((PlayerInfo*)(currentPeer->data))->haveGrowId == false) continue;
													world->owner = ((PlayerInfo*)(currentPeer->data))->rawName;
													world->ownerID = ((PlayerInfo*)(currentPeer->data))->userID;
													GamePacket p1 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oPlayer `2" + name + "`o is the world owner " + name + "!"));
													ENetPacket* packet1 = enet_packet_create(p1.data,
														p1.len,
														ENET_PACKET_FLAG_RELIABLE);

													enet_peer_send(currentPeer, 0, packet1);
													delete p1.data;
												}
											}
										}
									}
								}
							}
						}
						else if (str.substr(0, 5) == "/take") {
							if (((PlayerInfo*)(peer->data))->adminLevel == 1337) {
								{
									if (world->name != "ADMIN") {
										if (world->owner != "") {
											if (((PlayerInfo*)(peer->data))->adminLevel == 1337)

											{
												world->owner = ((PlayerInfo*)(peer->data))->rawName;
												world->ownerID = ((PlayerInfo*)(peer->data))->userID;
												ENetPeer* currentPeer;


												sendConsoleMsg(peer, "`2You took the world!");
											}

										}
									}
								}
							}
						}
						else if (str.substr(0, 4) == "/se ") {
							if (((PlayerInfo*)(peer->data))->adminLevel >= 444) {
								GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/pop_up_button.rttex"), str.substr(4, cch.length() - 4 - 1).c_str()), "audio/hub_open.wav"), 0));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									enet_peer_send(currentPeer, 0, packet);
								}
								//enet_host_flush(server);
								delete p.data;
							}
						}
						else if (str == "/online") {
							string online = "";
							int total = 0;
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->adminLevel >= 0) {
									online += ((PlayerInfo*)(currentPeer->data))->displayName + "`o, `w";
									total++;
								}
							}
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `5Players online [`wTotal: `2" + to_string(total) + "`5]: `w" + online));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else if (str.substr(0, 7) == "/color ")
							{
							((PlayerInfo*)(peer->data))->skinColor = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
							sendClothes(peer);
							}
						
						else if (str == "/invis") {
							cout << "[!] /invis from " << ((PlayerInfo*)(peer->data))->displayName << endl;
							if (((PlayerInfo*)(peer->data))->adminLevel >= 111) {
								sendConsoleMsg(peer, "`6" + str);
								if (!((PlayerInfo*)(peer->data))->isGhost) {

									sendConsoleMsg(peer, "`oSilent,invisible,deadly.(`$Ninja Stealth `omod added)");
									GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y));
									memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet2);
									delete p2.data;
									string text = "action|play_sfx\nfile|audio/boo_ghost_be_gone.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length());
									memcpy(data + 4 + text.length(), &zero, 1);
									ENetPacket* packet6 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packet6);
									delete data;
									sendState(peer);
									sendClothes(peer);
									((PlayerInfo*)(peer->data))->isGhost = true;
								}
							}
						}
						else if (str.substr(0, 7) == "/unacc ") {
						if (((PlayerInfo*)(peer->data))->rawName == world->owner) {

							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(currentPeer->data))->rawName == (str.substr(7, cch.length() - 7 - 1))) {
									WorldInfo info;
									world->acclist.erase(std::remove(world->acclist.begin(), world->acclist.end(), ((PlayerInfo*)(currentPeer->data))->rawName), world->acclist.end());
								}
							}
						}
						}
						else if (str.substr(0, 8) == "/access ") {
							if (((PlayerInfo*)(peer->data))->rawName == world->owner) {

								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(currentPeer->data))->rawName == (str.substr(8, cch.length() - 8 - 1))) {
										if (((PlayerInfo*)(peer->data))->rawName == ((PlayerInfo*)(currentPeer->data))->rawName) {
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You can't access yourself"));
											ENetPacket* packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet);
											delete p.data;
										}
										else {
											string text = "action|play_sfx\nfile|audio/secret.wav\ndelayMS|0\n";
											BYTE* data = new BYTE[5 + text.length()];
											BYTE zero = 0;
											int type = 3;
											memcpy(data, &type, 4);
											memcpy(data + 4, text.c_str(), text.length());
											memcpy(data + 4 + text.length(), &zero, 1);
											ENetPacket* packet2 = enet_packet_create(data,
												5 + text.length(),
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet2);
											delete data;
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `2" + world->owner + " `owants to add you to a World Lock. Wrench yourself to accept."));
											ENetPacket* packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet);
											delete p.data;
											((PlayerInfo*)(currentPeer->data))->isAccess = true;
										}
									}
								}
							}
						}
						else if (str == "/vis") {
							cout << "[!] /vis from " << ((PlayerInfo*)(peer->data))->displayName << endl;
							if (((PlayerInfo*)(peer->data))->adminLevel >= 111) {
								sendConsoleMsg(peer, "`oOthers `2can`o see you now!");

								GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), ((PlayerInfo*)(peer->data))->x1, ((PlayerInfo*)(peer->data))->y1));
								memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet2);
								delete p2.data;
								((PlayerInfo*)(peer->data))->isInvisible = false;
								sendState(peer);
								sendClothes(peer);
								((PlayerInfo*)(peer->data))->isGhost = false;

								/*GamePacket p = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 89), ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -3 : 3)), ((PlayerInfo*)(peer->data))->y));
							ENetPacket* packet3 = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet3);*/
								ENetPeer* currentPeer;
								GamePacket penter1 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 105), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 11));
								GamePacket penter2 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 105), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 12));
								GamePacket penter3 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 105), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 13));
								GamePacket penter4 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 105), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 14));
								GamePacket penter8 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 105), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 15));
								GamePacket penter5 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 105), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 16));
								GamePacket penter6 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 105), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 17));
								GamePacket penter7 = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), 105), ((PlayerInfo*)peer->data)->x1 + 10, ((PlayerInfo*)peer->data)->y1 + 18));
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{
										if (!((PlayerInfo*)(peer->data))->isGhost)
										{
											ENetPacket* packet5 = enet_packet_create(penter1.data,
												penter1.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet5);

											ENetPacket* packet6 = enet_packet_create(penter2.data,
												penter2.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet6);

											ENetPacket* packet7 = enet_packet_create(penter3.data,
												penter3.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet7);

											ENetPacket* packet8 = enet_packet_create(penter4.data,
												penter4.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet8);

											ENetPacket* packet9 = enet_packet_create(penter5.data,
												penter5.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet9);

											ENetPacket* packet10 = enet_packet_create(penter6.data,
												penter6.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet10);

											ENetPacket* packet11 = enet_packet_create(penter7.data,
												penter7.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet11);

											ENetPacket* packet12 = enet_packet_create(penter8.data,
												penter8.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet12);
										}
									}
								}
							}
						}
						else if (str.substr(0, 10) == "/particle ") {
							int x = ((PlayerInfo*)(peer->data))->x;
							int y = ((PlayerInfo*)(peer->data))->y;
							GamePacket psp = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), stoi(str.substr(10, cch.length() - 10 - 1))), x, y));

							ENetPacket* packetd = enet_packet_create(psp.data,
								psp.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetd);
							delete psp.data;
						}
						else if (str.substr(0, 4) == "/sb ") {
							using namespace std::chrono;
							if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
							{
								((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
							}
							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Wait a minute before using the SB command again!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
								continue;
							}
							
							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:0_PL:2_OID:_CT:[SB]_ `5** `5from `5(`$" + name + "`5) in [`$" + ((PlayerInfo*)(peer->data))->currentWorld + "`5] ** : `$ " + str.substr(4, cch.length() - 4 - 1)));
							string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (!((PlayerInfo*)(currentPeer->data))->radio)
									continue;
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet);




								ENetPacket* packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);

								//enet_host_flush(server);
							}
							delete data;
							delete p.data;
						}
						else if (str.substr(0, 5) == "/vsb ") {
							using namespace std::chrono;
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) < 111) break;
							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:0_PL:2_OID:_CT:[SB]_ `w** `5[`$THE RECLUSE-SB`5]```5 from `$`6" + name + "`````5in [`4JAMMED!`5]** :`` `& " + str.substr(5, cch.length() - 5 - 1)));
							string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (!((PlayerInfo*)(currentPeer->data))->radio)
									continue;
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet);




								ENetPacket* packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);

								//enet_host_flush(server);
							}
							delete data;
							delete p.data;
						}
						else if (str.substr(0, 5) == "/msb ") {
							using namespace std::chrono;
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) < 444) break;

							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:0_PL:2_OID:_CT:[SB]_ `w** `5[`#THE AMBITIOUS-SB`5]```5 from `6" + name + "`````5in [`4HIDDEN!`5] ** :`` `^ " + str.substr(5, cch.length() - 5 - 1)));
							string text = "action|play_sfx\nfile|audio/getpoint.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (!((PlayerInfo*)(currentPeer->data))->radio)
									continue;
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet);




								ENetPacket* packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);

								//enet_host_flush(server);
							}
							delete data;
							delete p.data;
						}
						else if (str.substr(0, 5) == "/ace ") {
						using namespace std::chrono;
						if (((PlayerInfo*)(peer->data))->level < 200) break;

						string name = ((PlayerInfo*)(peer->data))->displayName;
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:0_PL:2_OID:_CT:[SB]_ `w** `5[`5A`w-`4C`w-`9E `wSB`5]```5 from `6" + name + "`````5in [`$" + ((PlayerInfo*)(peer->data))->currentWorld + "`5] ** :`` `^ " + str.substr(5, cch.length() - 5 - 1)));
						string text = "action|play_sfx\nfile|audio/getpoint.wav\ndelayMS|0\n";
						BYTE* data = new BYTE[5 + text.length()];
						BYTE zero = 0;
						int type = 3;
						memcpy(data, &type, 4);
						memcpy(data + 4, text.c_str(), text.length());
						memcpy(data + 4 + text.length(), &zero, 1);
						ENetPeer* currentPeer;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							if (!((PlayerInfo*)(currentPeer->data))->radio)
								continue;
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet);




							ENetPacket* packet2 = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(currentPeer, 0, packet2);

							//enet_host_flush(server);
						}
						delete data;
						delete p.data;
						}
						
						else if (str.substr(0, 5) == "/cob ") {
							using namespace std::chrono;
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) < 777) break;

							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:0_PL:2_OID:_CT:[SB]_ `w** `5[`eSCO-SB`5]```6 from `$`9" + name + "`````5in [`4HIDDEN!`5] ** :`` `9 " + str.substr(5, cch.length() - 5 - 1)));
							string text = "action|play_sfx\nfile|audio/getpoint.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (!((PlayerInfo*)(currentPeer->data))->radio)
									continue;
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet);




								ENetPacket* packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);

								//enet_host_flush(server);
							}
							delete data;
							delete p.data;
						}
						
						else if (str.substr(0, 5) == "/osb ") {
							using namespace std::chrono;
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) < 1337) break;

							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] CP:0_PL:2_OID:_CT:[SB]_ `w** `b[`cTHE JUDGE-SB`b]```w from `$`6" + name + "```` `w(in `4UNKNOWN!`w) ** :`` `5 " + str.substr(5, cch.length() - 5 - 1)));
							string text = "action|play_sfx\nfile|audio/double_chance.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (!((PlayerInfo*)(currentPeer->data))->radio)
									continue;
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet);




								ENetPacket* packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);

								//enet_host_flush(server);
							}
							delete data;
							delete p.data;
						}
						else if (str.substr(0, 5) == "/jsb ") {
							using namespace std::chrono;
							if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
							{
								((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
							}
							else {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Wait a minute before using the JSB command again!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_host_flush(server);
								continue;
							}

							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `w** `5Super-Broadcast`` from `$`2" + name + "```` (in `4JAMMED``) ** :`` `# " + str.substr(5, cch.length() - 5 - 1)));
							string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPeer* currentPeer;

							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (!((PlayerInfo*)(currentPeer->data))->radio)
									continue;
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet);




								ENetPacket* packet2 = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(currentPeer, 0, packet2);

								//enet_host_flush(server);
							}
							delete data;
							delete p.data;
						}


						else if (str.substr(0, 6) == "/radio") {
							GamePacket p;
							if (((PlayerInfo*)(peer->data))->radio) {
								p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You won't see broadcasts anymore."));
								((PlayerInfo*)(peer->data))->radio = false;
							}
							else {
								p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You will now see broadcasts again."));
								((PlayerInfo*)(peer->data))->radio = true;
							}

							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet);
							delete p.data;
							//enet_host_flush(server);
						}
						else if (str.substr(0, 6) == "/reset") {
							if (adminlevel(((PlayerInfo*)(peer->data))->rawName) != 1337) break;
							cout << "[!] Restart from " << ((PlayerInfo*)(peer->data))->displayName << endl;
							GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/science_button.rttex"), "Restarting soon!"), "audio/mp3/suspended.mp3"), 0));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								enet_peer_send(currentPeer, 0, packet);
							}
							delete p.data;
							//enet_host_flush(server);
						}
						else if (str == "/unmod")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oModerator mode has been `4disabled`o! You will not able to walk through blocks!``"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							string text = "action|play_sfx\nfile|audio/dialog_cancel.wav\ndelayMS|0\n";
							BYTE* data = new BYTE[5 + text.length()];
							BYTE zero = 0;
							int type = 3;
							memcpy(data, &type, 4);
							memcpy(data + 4, text.c_str(), text.length());
							memcpy(data + 4 + text.length(), &zero, 1);
							ENetPacket* packet2 = enet_packet_create(data,
								5 + text.length(),
								ENET_PACKET_FLAG_RELIABLE);

							enet_peer_send(peer, 0, packet2);
							delete p.data;
							delete data;
							((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
							sendState(peer);
							/*PlayerMoving data;
							data.packetType = 0x14;
							data.characterState = 0x0; // animation
							data.x = 1000;
							data.y = 1;
							data.punchX = 0;
							data.punchY = 0;
							data.XSpeed = 300;
							data.YSpeed = 600;
							data.netID = ((PlayerInfo*)(peer->data))->netID;
							data.plantingTree = 0x0;
							SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/
						}
					}
					if (!((PlayerInfo*)(event.peer->data))->isIn)
					{
						if (itemdathash == 0) {
							enet_peer_disconnect_later(peer, 0);
						}
						GamePacket p = packetEnd(appendString(appendString(appendString(appendString(appendInt(appendString(createPacket(), "OnSuperMainStartAcceptLogonHrdxs47254722215a"), itemdathash), "ubistatic-a.akamaihd.net"), "0098/CDNContent60/cache/"), "cc.cz.madkite.freedom org.aqua.gg idv.aqua.bulldog com.cih.gamecih2 com.cih.gamecih com.cih.game_cih cn.maocai.gamekiller com.gmd.speedtime org.dax.attack com.x0.strai.frep com.x0.strai.free org.cheatengine.cegui org.sbtools.gamehack com.skgames.traffikrider org.sbtoods.gamehaca com.skype.ralder org.cheatengine.cegui.xx.multi1458919170111 com.prohiro.macro me.autotouch.autotouch com.cygery.repetitouch.free com.cygery.repetitouch.pro com.proziro.zacro com.slash.gamebuster"), "proto=95|choosemusic=audio/mp3/" + music + ".mp3|active_holiday=0"));
						//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
						ENetPacket* packet = enet_packet_create(p.data,
							p.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);

						//enet_host_flush(server);
						delete p.data;
						std::stringstream ss(GetTextPointerFromPacket(event.packet));
						std::string to;
						while (std::getline(ss, to, '\n')) {
							string id = to.substr(0, to.find("|"));
							string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
							if (id == "tankIDName")
							{
								((PlayerInfo*)(event.peer->data))->haveGrowId = true;
								((PlayerInfo*)(event.peer->data))->tankIDName = act;
							}
							else if (id == "tankIDPass")
							{
								((PlayerInfo*)(event.peer->data))->tankIDPass = act;
							}
							else if (id == "requestedName")
							{
								((PlayerInfo*)(event.peer->data))->requestedName = act;
							}
							else if (id == "country")
							{
								((PlayerInfo*)(event.peer->data))->country = act;
							}
							else if (id == "mac")
							{
								((PlayerInfo*)(event.peer->data))->macaddress = act;
							}
							else if (id == "f")
							{
								((PlayerInfo*)(event.peer->data))->f = act;
							}
							else if (id == "protocol")
							{
								((PlayerInfo*)(event.peer->data))->protocol = act;
							}
							else if (id == "game_version")
							{
								((PlayerInfo*)(event.peer->data))->gameVersion = act;
							}
							else if (id == "fz")
							{
								((PlayerInfo*)(event.peer->data))->fz = act;
							}
							else if (id == "lmode")
							{
								((PlayerInfo*)(event.peer->data))->lmode = act;
							}
							else if (id == "cbits")
							{
								((PlayerInfo*)(event.peer->data))->cbits = act;
							}
							else if (id == "player_age")
							{
								((PlayerInfo*)(event.peer->data))->playerage = act;
							}
							else if (id == "GDPR")
							{
								((PlayerInfo*)(event.peer->data))->GDPR = act;
							}
							else if (id == "hash2")
							{
								((PlayerInfo*)(event.peer->data))->hash2 = act;
							}
							else if (id == "meta")
							{
								((PlayerInfo*)(event.peer->data))->metaip = act;
							}
							else if (id == "fhash")
							{
								((PlayerInfo*)(event.peer->data))->fhash = act;
							}
							else if (id == "rid")
							{
								((PlayerInfo*)(event.peer->data))->rid = act;
							}
							else if (id == "platformID")
							{
								((PlayerInfo*)(event.peer->data))->platformid = act;
							}
							else if (id == "deviceVersion")
							{
								((PlayerInfo*)(event.peer->data))->deviceversion = act;
							}
							else if (id == "hash")
							{
								((PlayerInfo*)(event.peer->data))->hash = act;
							}
							else if (id == "mac")
							{
								((PlayerInfo*)(event.peer->data))->mac = act;
							}
							else if (id == "reconnect")
							{
								((PlayerInfo*)(event.peer->data))->reconnect = act;
							}
							else if (id == "wk")
							{
								bool valid = true;
								if (act.substr(0, 4) == "NONE" || act.substr(1, 4) == "NONE" || act.substr(3, 4) == "NONE") valid = false;
								if (valid) {
									((PlayerInfo*)(event.peer->data))->wk = act;

								}
							}
							else if (id == "zf")
							{
								((PlayerInfo*)(event.peer->data))->zf = act;
							}
						}
						if (!((PlayerInfo*)(event.peer->data))->haveGrowId)
						{
							((PlayerInfo*)(event.peer->data))->displayName = "" + PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->requestedName.substr(0, ((PlayerInfo*)(event.peer->data))->requestedName.length() > 15 ? 15 : ((PlayerInfo*)(event.peer->data))->requestedName.length()) + "_" + std::to_string(event.peer->address.host));
							((PlayerInfo*)(event.peer->data))->tankIDName = "" + PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->requestedName.substr(0, ((PlayerInfo*)(event.peer->data))->requestedName.length() > 15 ? 15 : ((PlayerInfo*)(event.peer->data))->requestedName.length()) + "_" + std::to_string(event.peer->address.host));
							((PlayerInfo*)(event.peer->data))->rawName = std::to_string(event.peer->address.host);
							
						}
						else {
							((PlayerInfo*)(event.peer->data))->rawName = PlayerDB::getProperName(((PlayerInfo*)(event.peer->data))->tankIDName);
#ifdef REGISTRATION
							int logStatus = PlayerDB::playerLogin(peer, ((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass);
							if (logStatus == -10) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Illegal name."));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								enet_peer_disconnect_later(peer, 0);
							}
							if (logStatus == -5) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `@Your connection have been cancelled!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								enet_peer_disconnect_later(peer, 0);
							}
							if (logStatus == -4) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Your account have been locked for security reasons, If you believe its an mistake please contact mindpin3289!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								enet_peer_disconnect_later(peer, 0);
							}
							if (logStatus == -5) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Your name is over 18 letter ! Please change"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								enet_peer_disconnect_later(peer, 0);
							}
							if (logStatus == -3) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4Sorry, this account (`5" + ((PlayerInfo*)(event.peer->data))->rawName + "`4) has been suspended.If you have a question contact `5mindpin#3289`4!"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
								//enet_peer_disconnect_later(peer, 0);
							}
							else if (logStatus == 1) {
								PlayerInfo* p = ((PlayerInfo*)(peer->data));
								std::ifstream ifff("players/" + PlayerDB::getProperName(p->rawName) + ".json");
								json j;
								ifff >> j;

								int gems, wls, ban, bandate, bantime, adminLevel, rubble, back, hand, face, hair, feet, pants, neck, shirt, mask, ances, lgn, ldrg, lwhip, join, lwng, lvl, xp;
								bool joinguild, milk, legend, online;
								gems = j["gems"];
								wls = j["wls"];
								adminLevel = j["adminLevel"];
								back = j["ClothBack"];
								hand = j["ClothHand"];
								face = j["ClothFace"];
								hair = j["ClothHair"];
								feet = j["ClothFeet"];
								pants = j["ClothPants"];
								neck = j["ClothNeck"];
								shirt = j["ClothShirt"];
								mask = j["ClothMask"];
								ances = j["ClothAnces"];
								ban = j["ban"];
								bandate = j["bandate"];
								bantime = j["bantime"];
								lvl = j["level"];
								xp = j["xp"];
								string guild;
								if (j.count("guild") == 1) {
									guild = j["guild"];
								}
								else {
									guild = "";
								}
								if (j.count("joinguild") == 1) {
									joinguild = j["joinguild"];
								}
								else {
									joinguild = false;
								}
								if (j.count("milk") == 1) {
									milk = j["milk"];
								}
								else {
									milk = false;
								}
								if (j.count("legend") == 1) {
									legend = j["legend"];
								}
								else {
									legend = false;
								}
								if (j.count("online") == 1) {
									online = j["online"];
								}
								else {
								    online = false;
								}
								p->gem = gems;
								p->ban = ban;
								p->wls = wls;
								p->xp = xp;
								p->level = lvl;
								p->guild = guild;
								p->joinguild = joinguild;
								p->adminLevel = adminLevel;
								p->cloth_back = back;
								p->cloth_hand = hand;
								p->cloth_face = face;
								p->cloth_hair = hair;
								p->cloth_feet = feet;
								p->cloth_pants = pants;
								p->cloth_necklace = neck;
								p->cloth_shirt = shirt;
								p->cloth_mask = mask;
								p->cloth_ances = ances;
								p->ban = ban;
								p->bandate = bandate;
								p->bantime = bantime;
								p->online = online;
								p->milk = milk;
								p->legend = legend;

								updateAllClothes(peer);

								ifff.close();

								short invsize = 0;
								ifstream invfd("usersinventorysize/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
								invfd >> invsize;
								invfd.close();
								string guildname = PlayerDB::getProperName(((PlayerInfo*)(peer->data))->guild);
								if (guildname != "") {
									std::ifstream ifff("guilds/" + guildname + ".json");
									if (ifff.fail()) {
										ifff.close();
										cout << "[!] Failed loading guilds/" + guildname + ".json! From " + ((PlayerInfo*)(peer->data))->displayName + "." << endl;
										((PlayerInfo*)(peer->data))->guild = "";

									}
									json j;
									ifff >> j;

									int gfbg, gffg;

									string gstatement, gleader;

									vector<string> gmembers;

									gfbg = j["backgroundflag"];
									gffg = j["foregroundflag"];
									gstatement = j["GuildStatement"];
									gleader = j["Leader"];
									for (int i = 0; i < j["Member"].size(); i++) {
										gmembers.push_back(j["Member"][i]);
									}

									((PlayerInfo*)(peer->data))->guildBg = gfbg;
									((PlayerInfo*)(peer->data))->guildFg = gffg;
									((PlayerInfo*)(peer->data))->guildStatement = gstatement;
									((PlayerInfo*)(peer->data))->guildLeader = gleader;
									((PlayerInfo*)(peer->data))->guildMembers = gmembers;

									ifff.close();
								}
								((PlayerInfo*)(peer->data))->currentInventorySize = invsize;
								GamePacket p5 = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packet5 = enet_packet_create(p5.data,
									p5.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet5);
								delete p5.data;
								sendConsoleMsg(peer, "`w[`2+`w] `1Connecting... `w[`cGrowtalePS `b- `2GrowtopiaNoobs`w]");
								((PlayerInfo*)(event.peer->data))->displayName = ((PlayerInfo*)(event.peer->data))->tankIDName;
								if (((PlayerInfo*)(peer->data))->adminLevel == 1337) {
									((PlayerInfo*)(event.peer->data))->displayName = "`c@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
								}
								else if (((PlayerInfo*)(peer->data))->adminLevel == 999) {
									((PlayerInfo*)(event.peer->data))->displayName = "`6@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
								}
								else if (((PlayerInfo*)(peer->data))->adminLevel == 777) {
									((PlayerInfo*)(event.peer->data))->displayName = "`4@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
								}
								else if (((PlayerInfo*)(peer->data))->adminLevel == 666) {
									((PlayerInfo*)(event.peer->data))->displayName = "`w[`4Administrator`w] " + ((PlayerInfo*)(event.peer->data))->tankIDName;
								}
								else if (((PlayerInfo*)(peer->data))->adminLevel == 444) {
									((PlayerInfo*)(event.peer->data))->displayName = "`#@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
								}
								else if (((PlayerInfo*)(peer->data))->adminLevel == 444) {
									((PlayerInfo*)(event.peer->data))->displayName = "`$@" + ((PlayerInfo*)(event.peer->data))->tankIDName;
								}
								else {
									((PlayerInfo*)(event.peer->data))->displayName = ((PlayerInfo*)(event.peer->data))->tankIDName;
								}

							}
							else {
							wrongpass(peer);
							enet_peer_disconnect_later(peer, 0);
							}
#else

							((PlayerInfo*)(event.peer->data))->displayName = PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->tankIDName.substr(0, ((PlayerInfo*)(event.peer->data))->tankIDName.length() > 18 ? 18 : ((PlayerInfo*)(event.peer->data))->tankIDName.length()));
							if (((PlayerInfo*)(event.peer->data))->displayName.length() < 3) ((PlayerInfo*)(event.peer->data))->displayName = "Person that doesn't know how the name looks!";
#endif
						}
						for (char c : ((PlayerInfo*)(event.peer->data))->displayName) if (c < 0x20 || c>0x7A) ((PlayerInfo*)(event.peer->data))->displayName = "Bad characters in name, remove them!";

						if (((PlayerInfo*)(event.peer->data))->country.length() > 4)
						{
							//((PlayerInfo*)(event.peer->data))->country = "us";
						}
						if (((PlayerInfo*)(event.peer->data))->adminLevel == 1337)
						{
							((PlayerInfo*)(event.peer->data))->country = "rt|maxLevel";
						}
						if (((PlayerInfo*)(event.peer->data))->level >= 50)
						{
							((PlayerInfo*)(event.peer->data))->country = "|maxLevel";
						}
						/*GamePacket p3= packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
						//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
						ENetPacket * packet3 = enet_packet_create(p3.data,
						p3.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet3);
						enet_host_flush(server);*/


						GamePacket p2 = packetEnd(appendString(appendString(appendInt(appendString(createPacket(), "SetHasGrowID"), ((PlayerInfo*)(event.peer->data))->haveGrowId), ((PlayerInfo*)(peer->data))->tankIDName), ((PlayerInfo*)(peer->data))->tankIDPass));
						ENetPacket* packet2 = enet_packet_create(p2.data,
							p2.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2);
						delete p2.data;



					}
					string pStr = GetTextPointerFromPacket(event.packet);
					//if (strcmp(GetTextPointerFromPacket(event.packet), "action|enter_game\n") == 0 && !((PlayerInfo*)(event.peer->data))->isIn)
					if (pStr.substr(0, 17) == "action|enter_game" && !((PlayerInfo*)(event.peer->data))->isIn)
					{
#ifdef TOTAL_LOG
						cout << "[!] And we are in!" << endl;
#endif
						((PlayerInfo*)(event.peer->data))->isIn = true;
						ENetPeer* currentPeer;
						/*for (currentPeer = server->peers;
						currentPeer < &server->peers[server->peerCount];
						++currentPeer)
						{
						if (currentPeer->state != ENET_PEER_STATE_CONNECTED)isIn
						continue;


						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Player `o" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`o just entered the game..."));
						ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(currentPeer, 0, packet);

						enet_host_flush(server);
						delete p.data;
						}*/
						if (((PlayerInfo*)(peer->data))->haveGrowId) {
							sendWorldOffers(peer);
						}
						int counts = 0;

						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							counts++;
						}
						if (((PlayerInfo*)(peer->data))->haveGrowId) {
							string name = ((PlayerInfo*)(peer->data))->displayName;
							GamePacket p7 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"));
							ENetPacket* packet7 = enet_packet_create(p7.data,
								p7.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet7);
							delete p7.data;
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `wWelcome back, " + name + "`o. `e(`wThere are `1" + to_string(counts) + " `wplayers online!`e)"));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
							sendGazette(peer);
							GamePacket p2ssw = packetEnd(appendString(appendInt(appendString(createPacket(), "OnEmoticonDataChanged"), 201560520), "(wl)|ā|1&(yes)|Ă|1&(no)|ă|1&(love)|Ą|1&(oops)|ą|1&(shy)|Ć|1&(wink)|ć|1&(tongue)|Ĉ|1&(agree)|ĉ|1&(sleep)|Ċ|1&(punch)|ċ|1&(music)|Č|1&(build)|č|1&(megaphone)|Ď|1&(sigh)|ď|1&(mad)|Đ|1&(wow)|đ|1&(dance)|Ē|1&(see-no-evil)|ē|1&(bheart)|Ĕ|1&(heart)|ĕ|1&(grow)|Ė|1&(gems)|ė|1&(kiss)|Ę|1&(gtoken)|ę|1&(lol)|Ě|1&(smile)|Ā|1&(cool)|Ĝ|1&(cry)|ĝ|1&(vend)|Ğ|1&(bunny)|ě|1&(cactus)|ğ|1&(pine)|Ĥ|1&(peace)|ģ|1&(terror)|ġ|1&(troll)|Ģ|1&(evil)|Ģ|1&(fireworks)|Ħ|1&(football)|ĥ|1&(alien)|ħ|1&(party)|Ĩ|1&(pizza)|ĩ|1&(clap)|Ī|1&(song)|ī|1&(ghost)|Ĭ|1&(nuke)|ĭ|1&(halo)|Į|1&(turkey)|į|1&(gift)|İ|1&(cake)|ı|1&(heartarrow)|Ĳ|1&(lucky)|ĳ|1&(shamrock)|Ĵ|1&(grin)|ĵ|1&(ill)|Ķ|1&"));
							ENetPacket* packet2ssw = enet_packet_create(p2ssw.data,
								p2ssw.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2ssw);
							delete p2ssw.data;

							//enet_host_flush(server);
							std::ifstream ifff("inventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");

							if (ifff.fail()) {
								ifff.close();


							}
							if (ifff.is_open()) {


							}
							json j;
							ifff >> j; //load

							if (j["items"][0]["itemid"] != 18 || j["items"][1]["itemid"] != 32)
							{
								j["items"][0]["itemid"] = 18;
								j["items"][1]["itemid"] = 32;

								j["items"][0]["quantity"] = 1;
								j["items"][1]["quantity"] = 1;

								std::ofstream oo("inventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
								if (!oo.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}
								oo << j << std::endl;
								//cout << "[!] zaidejas " << ((PlayerInfo*)(peer->data))->rawName << " prisijunkdamas turejo inventoriuje pirmus 2 elementus ne ranka arba ne wrench." << endl;
							}

							PlayerInventory inventory;
							{
								InventoryItem item;

								for (int i = 0; i < ((PlayerInfo*)(peer->data))->currentInventorySize; i++)
								{
									int itemid = j["items"][i]["itemid"];
									int quantity = j["items"][i]["quantity"];
									if (itemid != 0 && quantity != 0)
									{
										item.itemCount = quantity;
										item.itemID = itemid;
										inventory.items.push_back(item);
										sendInventory(peer, inventory);
									}

								}
							}
							((PlayerInfo*)(event.peer->data))->inventory = inventory;
						}
						else {
							if (configPort == 8080) {
								GamePacket p3 = packetEnd(appendInt(appendInt(appendString(appendString(createPacket(), "OnRedirectServer"), "52.168.136.31"), 17091), 1));

								//memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
								ENetPacket* packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packet3);
								delete p3.data;
							}
							else {
								GamePacket p2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/tutorial/tut07_create_world.rttex"), "`oLet's create a worlds! You can create a worlds by enter a random worlds and lock it!"), "audio/tip_start.wav"), 1));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);

								//enet_host_flush(server);
								delete p2.data;
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wWelcome!|left|18|\nadd_spacer|small|\nadd_label|small|`wHello Guest! Welcome to the Growtale Private Server! We will teach you the basics!|left|\nadd_spacer|small|\nadd_label_with_icon|small|`wOnce you've mastered the basics. you'll visit the `5START `wworld where you can interact with people and make friend here!|left|20|\nadd_spacer|\nadd_button|skiptutorial|`2Explore & Play `w[`1Skip Tutorial`w]|0|0|noflags|\nadd_button|tutorial|`wShow Tutorial!|0|0|noflags|\n"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);

								//enet_host_flush(server);
								delete p.data;
								PlayerInventory inventory;
								for (int i = 0; i < 200; i++)
								{
									InventoryItem it;
									it.itemID = (i * 2) + 2;
									it.itemCount = 200;
									inventory.items.push_back(it);
								}
								((PlayerInfo*)(event.peer->data))->inventory = inventory;
								joinWorld(peer, "START", 0, 0);
							}
						}

					}
					if (strcmp(GetTextPointerFromPacket(event.packet), "action|refresh_item_data\n") == 0)
					{
						if (itemsDat != NULL) {
							ENetPacket* packet = enet_packet_create(itemsDat,
								itemsDatSize + 60,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							((PlayerInfo*)(peer->data))->isUpdating = true;
							enet_peer_disconnect_later(peer, 0);
							//enet_host_flush(server);
						}
						// TODO FIX refresh_item_data ^^^^^^^^^^^^^^
					}
					break;
				}
				default:
					cout << "[!] Unknown packet type " << messageType << endl;
					enet_peer_reset(peer);
					break;
				case 3:
				{
					bool isValidateReq = false;
					//cout << GetTextPointerFromPacket(event.packet) << endl;
					std::stringstream ss(GetTextPointerFromPacket(event.packet));
					std::string to;
					bool isJoinReq = false;
					while (std::getline(ss, to, '\n')) {
						string id = to.substr(0, to.find("|"));
						string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
						if (id == "name" && isJoinReq)
						{
#ifdef TOTAL_LOG
							cout << "[!] Entering some world..." << endl;
#endif
							toUpperCase(act);



							if (act.find(" ") != string::npos || act.find("  ") != string::npos || act.find(".") != string::npos || act.find(",") != string::npos || act.find("@") != string::npos || act.find("[") != string::npos || act.find("]") != string::npos || act.find("#") != string::npos || act.find("<") != string::npos || act.find(">") != string::npos || act.find(":") != string::npos || act.find("\"") != string::npos || act.find("{") != string::npos || act.find("}") != string::npos || act.find("|") != string::npos || act.find("+") != string::npos || act.find("_") != string::npos || act.find("~") != string::npos || act.find("-") != string::npos || act.find("!") != string::npos || act.find("$") != string::npos || act.find("%") != string::npos || act.find("^") != string::npos || act.find("&") != string::npos || act.find("`") != string::npos || act.find("*") != string::npos || act.find("(") != string::npos || act.find(")") != string::npos || act.find("=") != string::npos || act.find("'") != string::npos || act.find(";") != string::npos || act.find("/") != string::npos) {
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] You cant use symbols in world name.``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								GamePacket p3 = packetEnd(appendString(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1), "Sorry"));
								ENetPacket * packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet3);
								delete p3.data;

								continue;
								break;
							}
							if (act == "")
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Where are we going?``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								GamePacket p3 = packetEnd(appendString(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1), "Sorry"));
								ENetPacket * packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet3);
								delete p3.data;

								continue;
								break;
							}
							if (act == "")
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Where are we going?``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								GamePacket p3 = packetEnd(appendString(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1), "Sorry"));
								ENetPacket * packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet3);
								delete p3.data;

								continue;
								break;
							}
							if (act == "ADMIN" || act == "TEST")
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `4To reduce confusation this world is disabled.``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								GamePacket p3 = packetEnd(appendString(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1), "Sorry"));
								ENetPacket * packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet3);
								delete p3.data;

								continue;
								break;
							}
							if (act == "CON" || act == "EXIT" || act == "NUL" || act == "PRN" || act == "AUX" || act == "CLOCK$" || act == "COM0" || act == "COM1" || act == "COM2" || act == "COM3" || act == "COM4" || act == "COM5" || act == "COM6" || act == "COM7" || act == "COM8" || act == "COM9" || act == "LPT0" || act == "LPT1" || act == "LPT2" || act == "LPT3" || act == "LPT4" || act == "LPT5" || act == "LPT6" || act == "LPT7" || act == "LPT8" || act == "LPT9")
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Maybe try another one?``"));
								ENetPacket * packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								GamePacket p3 = packetEnd(appendString(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1), "Sorry"));
								ENetPacket * packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet3);
								delete p3.data;

								continue;
								break;
							}
							else
							{

								WorldInfo info = worldDB.get(act);
								WorldInfo info2 = worldDB.get("HELL");
								WorldInfo info3 = worldDB.get("START");

								string name = ((PlayerInfo*)(peer->data))->rawName;
								bool exitsnuke = info.isNuked == true;

								if (exitsnuke)
								{
									if (adminlevel(((PlayerInfo*)(peer->data))->rawName) >= 444) {
										joinWorld(peer, act, 0, 0);
										sendConsoleMsg(peer, "This world is inaccessible by others!");

									}
									else
									{

										GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] `oThis world is inaccessible.``"));
										ENetPacket * packet = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete p.data;

										GamePacket p3 = packetEnd(appendString(appendInt(appendString(createPacket(), "OnFailedToEnterWorld"), 1), "Sorry"));
										ENetPacket * packet3 = enet_packet_create(p3.data,
											p3.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet3);
										delete p3.data;

										continue;
										break;
									}
								}

								else
								{

									joinWorld(peer, act, 0, 0);
								}
							}
						}
						if (id == "action")
						{

							if (act == "join_request")
							{
								isJoinReq = true;
							}
							if (act == "quit_to_exit")
							{
								int count = 0;
								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									count++;
								}
								if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
									sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
									((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
									sendWorldOffers(peer);
								}
								else {
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnZoomCamera"), 2));
									ENetPacket* packet23 = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet23);
									delete p.data;
									GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet2);
									delete p2.data;
									GamePacket p25 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
									memcpy(p25.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
									ENetPacket* packet25 = enet_packet_create(p25.data,
										p25.len,
										ENET_PACKET_FLAG_RELIABLE);


									enet_peer_send(peer, 0, packet25);
									delete p25.data;
									GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Create your account first please."));
									ENetPacket* packet = enet_packet_create(ps.data,
										ps.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete ps.data;
									break;
								}

							}
							if (act == "quit")
							{
								enet_peer_disconnect_later(peer, 0);
								int count = 0;
								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									count++;
								}
								ofstream myfile;
								myfile.open("onlineplayer.txt");
								myfile << to_string(count);
								myfile.close();
							}
						}
					}
					break;
				}
				case 4:
				{
					{
						BYTE* tankUpdatePacket = GetStructPointerFromTankPacket(event.packet);

						if (tankUpdatePacket)
						{
							PlayerMoving* pMov = unpackPlayerMoving(tankUpdatePacket);

							if ((pMov->characterState >= 80 || pMov->characterState == 64) && pMov->characterState != 144 && pMov->characterState != 128 && pMov->characterState < 250) {
								if (((PlayerInfo*)(peer->data))->canWalkInBlocks == false)
								{
									((PlayerInfo*)(event.peer->data))->lavaLevel = ((PlayerInfo*)(event.peer->data))->lavaLevel + 1;

									if (((PlayerInfo*)(peer->data))->lavaLevel >= 5) {
										((PlayerInfo*)(peer->data))->lavaLevel = 0;
										int x = ((PlayerInfo*)(peer->data))->x;
										int y = ((PlayerInfo*)(peer->data))->y;
										for (int i = 0; i < world->width * world->height; i++)
										{
											if (world->items[i].foreground == 6) {
												x = (i % world->width) * 32;
												y = (i / world->width) * 32;
												//world->items[i].foreground = 8;
											}
										}
										playerRespawn(peer, false);
									}
								}
							}

							if (((PlayerInfo*)(peer->data))->currentWorld == "EXIT")
							{

								continue;

							}
						}
						if (tankUpdatePacket)
						{
							PlayerMoving* pMov = unpackPlayerMoving(tankUpdatePacket);
							if (((PlayerInfo*)(event.peer->data))->isGhost) {
								((PlayerInfo*)(event.peer->data))->isInvisible = true;
								((PlayerInfo*)(event.peer->data))->x1 = pMov->x;
								((PlayerInfo*)(event.peer->data))->y1 = pMov->y;
								pMov->x = -1000000;
								pMov->y = -1000000;
							}

							switch (pMov->packetType)
							{
							case 0:
								((PlayerInfo*)(event.peer->data))->x = pMov->x;
								((PlayerInfo*)(event.peer->data))->y = pMov->y;
								((PlayerInfo*)(event.peer->data))->isRotatedLeft = pMov->characterState & 0x10;
								sendPData(peer, pMov);
								if (!((PlayerInfo*)(peer->data))->joinClothesUpdated)
								{
									((PlayerInfo*)(peer->data))->joinClothesUpdated = true;
									updateAllClothes(peer);
									updateInvis(peer);
								}
								break;

							default:
								break;
							}
							int omgcheck = ((PlayerInfo*)(event.peer->data))->x + (((PlayerInfo*)(event.peer->data))->y * world->width);
							PlayerMoving* data2 = unpackPlayerMoving(tankUpdatePacket);
							//cout << data2->packetType << endl;
							if (data2->packetType == 25) {
								if (((PlayerInfo*)(peer->data))->adminLevel <= 444) {
									GamePacket ps2 = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/science_button.rttex"), "`wCrasher kontol, fucek buat lu"), "audio/hub_open.wav"), 0));
									ENetPacket * packet2 = enet_packet_create(ps2.data,
										ps2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet2);
									enet_peer_disconnect_now(peer, 0);
								}
							}
							if (data2->packetType == 11)
							{
								PlayerInfo* pinfo = ((PlayerInfo*)(event.peer->data));
								WorldInfo* world = getPlyersWorld(event.peer);
								if (!world) break;
								// is this legit collect?
								// nah, we're not checking for that
								bool legit = true;
								// ...
								// anticheat code goes here
								// ...
								int itemIdx = pMov->plantingTree - 1;
								int atik = -1;
								for (int i = 0; i < world->droppedItems.size(); i++)
								{
									if (world->droppedItems.at(i).uid == itemIdx)
									{
										atik = i;
										break;
									}
								}
								legit = atik != -1;
								if (legit)
								{
									//	cout << "[!] heh" << endl;
									DroppedItem droppedItem = world->droppedItems.at(atik);

									// check if player already has item

									legit = true;
								}
								if (legit)
								{
									DroppedItem droppedItem = world->droppedItems.at(atik);

									if (droppedItem.id == 112)
									{
										pinfo->gem += droppedItem.count;
										GamePacket pp = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
										int respawnTimeout = 1000;
										int deathFlag = 0x19;
										memcpy(pp.data + 24, &respawnTimeout, 4);
										memcpy(pp.data + 56, &deathFlag, 4);
										ENetPacket* packetpp = enet_packet_create(pp.data,
											pp.len,
											ENET_PACKET_FLAG_RELIABLE);

										enet_peer_send(peer, 0, packetpp);
										delete pp.data;
										savejson(peer);
									}
									else
									{
										bool success = true;
										SaveShopsItemMoreTimes(droppedItem.id, droppedItem.count, peer, success);
									}
									if (getItemDef(droppedItem.id).rarity == 999)
									{
										if (droppedItem.id != 112)
										{
											SendConsoleMsg(peer, "`oCollected `w" + to_string(droppedItem.count) + " " + getItemDef(droppedItem.id).name + "`o.");
										}
									}
									else
									{
										SendConsoleMsg(peer, "`oCollected `w" + to_string(droppedItem.count) + " " + getItemDef(droppedItem.id).name + "`o. Rarity: `w" + to_string(getItemDef(droppedItem.id).rarity) + "`o.");
									}
									world->droppedItems.erase(world->droppedItems.begin() + atik);
									SendTake(peer, pinfo->netID, pMov->x, pMov->y, itemIdx + 1);
								}
								else
								{
									//	cout << "[!] Couldn't take item - plantingTree value is " << hex << pMov->plantingTree << dec << " and itemIdx value is " << hex << itemIdx << dec << "!" << endl;
								}
							}
							if (data2->packetType == 7)
							{
								int x = pMov->punchX;
								int y = pMov->punchY;
								//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << endl;
								/*GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
								//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
								ENetPacket * packet3 = enet_packet_create(p3.data,
									p3.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet3);
								enet_host_flush(server);*/
								int tile = world->items[x + (y * world->width)].foreground;
								int idx = pMov->punchY * world->width + pMov->punchX;
								if (world->items[x + (y * world->width)].foreground == 6) {
									if (((PlayerInfo*)(event.peer->data))->haveGrowId == false) {
										GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnZoomCamera"), 2));
										ENetPacket* packet23 = enet_packet_create(p.data,
											p.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet23);
										delete p.data;
										GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
										ENetPacket* packet2 = enet_packet_create(p2.data,
											p2.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet2);
										delete p2.data;
										GamePacket p25 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
										memcpy(p25.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
										ENetPacket* packet25 = enet_packet_create(p25.data,
											p25.len,
											ENET_PACKET_FLAG_RELIABLE);


										enet_peer_send(peer, 0, packet25);
										delete p25.data;
										GamePacket ps = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "Create your account first please."));
										ENetPacket* packet = enet_packet_create(ps.data,
											ps.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packet);
										delete ps.data;
										break;
									}
									sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
									sendWorldOffers(peer);
									GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnZoomCamera"), -2));
									ENetPacket* packet23 = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet23);
									delete p.data;
									// lets take item
								}
								else if (getItemDef(world->items[idx].foreground).blockType == BlockTypes::DOOR)
								{
									PlayerInfo* pinf = (PlayerInfo*)peer->data;
									switch (world->items[idx].foreground)
									{
									case 762:
									case 4190:
										// Password Door
										if (world->items[idx].password == "")
										{
											// fail
											DoCancelTransitionAndTeleport(peer, pMov->punchX, pMov->punchY);
											sendChatMessage(peer, ((PlayerInfo*)(peer->data))->netID, "This door has no password set!");
										}
										else
										{
											pinf->wrenchsession = idx;
											DoCancelTransitionAndTeleport(peer, pMov->punchX, pMov->punchY);
											sendDialog(peer, "set_default_color|`o\n\nadd_label_with_icon|big|`w" + getItemDef(world->items[idx].foreground).name + "``|left|" + to_string(world->items[idx].foreground) + "|\n\nadd_spacer|small|\nadd_textbox|`oThis door requires a password.``|\nadd_text_input|doorpass|Password||100|\nend_dialog|pwddoor|Cancel|OK|");
										}
										break;
									default:
										DoEnterDoor(peer, world, pMov->punchX, pMov->punchY);
										break;
									}
								}
								else {
									((PlayerInfo*)(peer->data))->ischeck = true;
									((PlayerInfo*)(peer->data))->checkx = x * 32;
									((PlayerInfo*)(peer->data))->checky = y * 32;
									GamePacket p2 = packetEnd(appendInt(appendString(createPacket(), "SetRespawnPos"), x + (y * world->width)));
									memcpy(p2.data + 8, &((PlayerInfo*)(event.peer->data))->netID, 4);
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);


									enet_peer_send(peer, 0, packet2);


									delete p2.data;
								}
							}
							if (data2->packetType == 10)
							{
								int item = pMov->plantingTree;
								PlayerInfo* info = ((PlayerInfo*)(peer->data));
								ItemDefinition pro;
								pro = getItemDef(item);
								//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << ";" << pMov->punchY << ";" << pMov->characterState << endl;
								ItemDefinition def;
								try {
									def = getItemDef(pMov->plantingTree);
								}
								catch (int e) {
									goto END_CLOTHSETTER_FORCE;
								}
								switch (def.clothType) {
								case 0:
									if (((PlayerInfo*)(event.peer->data))->cloth0 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth0 = 0;
										getAutoEffect(peer);
										sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effect);
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth0 = pMov->plantingTree;
									sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effects);
									break;
								case 1:
									if (((PlayerInfo*)(event.peer->data))->cloth1 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth1 = 0;
										if (pMov->plantingTree = 1780) {
											info->peffect = 8421396;
											sendState(peer); //here
										}
										getAutoEffect(peer);
										sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effect);
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth1 = pMov->plantingTree;
									sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effects);
									break;
								case 2:
									if (((PlayerInfo*)(event.peer->data))->cloth2 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth2 = 0;
										getAutoEffect(peer);
										sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effect);
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth2 = pMov->plantingTree;
									sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effects);
									break;
								case 3:
									if (((PlayerInfo*)(event.peer->data))->cloth3 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth3 = 0;
										getAutoEffect(peer);
										sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effect);
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth3 = pMov->plantingTree;
									sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effects);
									break;
								case 4:
									if (((PlayerInfo*)(event.peer->data))->cloth4 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth4 = 0;
										getAutoEffect(peer);
										sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effect);
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth4 = pMov->plantingTree;
									sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effects);
									if (item == 1204) {
										info->peffect = 8421386;
									}
									else if (item == 138) {
										info->peffect = 8421377;
									}
									else if (item == 2476) {
										info->peffect = 8421415;
									}
									else {
										getAutoEffect(peer);
									}

									break;
								case 5:
									if (((PlayerInfo*)(event.peer->data))->cloth5 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth5 = 0;
										getAutoEffect(peer);
										sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effect);
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth5 = pMov->plantingTree;
									if (item == 366 || item == 1464) {
										info->peffect = 8421378;
									}
									else if (item == 1782) {
										info->peffect = 8421397;
									}
									else if (item == 366 || item == 1464) {
										info->peffect = 8421378;
									}
									else if (item == 472) {
										info->peffect = 8421379;
									}
									else if (item == 594) {
										info->peffect = 8421380;
									}
									else if (item == 768) {
										info->peffect = 8421381;
									}
									else if (item == 900) {
										info->peffect = 8421382;
									}
									else if (item == 910) {
										info->peffect = 8421383;
									}
									else if (item == 930) {
										info->peffect = 8421384;
									}
									else if (item == 1016) {
										info->peffect = 8421385;
									}
									else if (item == 1378) {
										info->peffect = 8421387;
									}
									else if (item == 1484) {
										info->peffect = 8421389;
									}
									else if (item == 1512) {
										info->peffect = 8421390;
									}
									else if (item == 1542) {
										info->peffect = 8421391;
									}
									else if (item == 1576) {
										info->peffect = 8421392;
									}
									else if (item == 1676) {
										info->peffect = 8421393;
									}
									else if (item == 1710) {
										info->peffect = 8421394;
									}
									else if (item == 1748) {
										info->peffect = 8421395;
									}
									else if (item == 1780) {
										info->peffect = 8421396;
									}
									else if (item == 1782) {
										info->peffect = 8421397;
									}
									else if (item == 1804) {
										info->peffect = 8421398;
									}
									else if (item == 1868) {
										info->peffect = 8421399;
									}
									else if (item == 1874) {
										info->peffect = 8421400;
									}
									else if (item == 1946) {
										info->peffect = 8421401;
									}
									else if (item == 1948) {
										info->peffect = 8421402;
									}
									else if (item == 1956) {
										info->peffect = 8421403;
									}
									else if (item == 2908) {
										info->peffect = 8421405;
									}
									else if (item == 2952) {
										info->peffect = 8421405;
									}
									else if (item == 6312) {
										info->peffect = 8421405;
									}
									else if (item == 1980) {
										info->peffect = 8421406;
									}
									else if (item == 2066) {
										info->peffect = 8421407;
									}
									else if (item == 2212) {
										info->peffect = 8421408;
									}
									else if (item == 2218) {
										info->peffect = 8421409;
									}
									else if (item == 2220) {
										info->peffect = 8421410;
									}
									else if (item == 2266) {
										info->peffect = 8421411;
									}
									else if (item == 2386) {
										info->peffect = 8421412;
									}
									else if (item == 2388) {
										info->peffect = 8421413;
									}
									else if (item == 2450) {
										info->peffect = 8421414;
									}
									else if (item == 2512) {
										info->peffect = 8421417;
									}
									else if (item == 2572) {
										info->peffect = 8421418;
									}
									else if (item == 2592) {
										info->peffect = 8421419;
									}
									else if (item == 7912) {
										info->peffect = 8421487;
									}
									else if (item == 2720) {
										info->peffect = 8421420;
									}
									else if (item == 2752) {
										info->peffect = 8421421;
									}
									else if (item == 2754) {
										info->peffect = 8421422;
									}
									else if (item == 2756) {
										info->peffect = 8421423;
									}
									else if (item == 2802) {
										info->peffect = 8421425;
									}
									else if (item == 2866) {
										info->peffect = 8421426;
									}
									else if (item == 2876) {
										info->peffect = 8421427;
									}
									else if (item == 2886) {
										info->peffect = 8421430;
									}
									else if (item == 2890) {
										info->peffect = 8421431;
									}
									else if (item == 3066) {
										info->peffect = 8421433;
									}
									else if (item == 3124) {
										info->peffect = 8421434;
									}
									else if (item == 3168) {
										info->peffect = 8421435;
									}
									else if (item == 3214) {
										info->peffect = 8421436;
									}
									else if (item == 3300) {
										info->peffect = 8421440;
									}
									else if (item == 3418) {
										info->peffect = 8421441;
									}
									else if (item == 3476) {
										info->peffect = 8421442;
									}
									else if (item == 3686) {
										info->peffect = 8421444;
									}
									else if (item == 3716) {
										info->peffect = 8421445;
									}
									else if (item == 4290) {
										info->peffect = 8421447;
									}
									else if (item == 4474) {
										info->peffect = 8421448;
									}
									else if (item == 4464) {
										info->peffect = 8421449;
									}
									else if (item == 1576) {
										info->peffect = 8421450;
									}
									else if (item == 5480) {
										info->peffect = 8421456;
									}
									else if (item == 4778 || item == 6026) {
										info->peffect = 8421452;
									}
									else if (item == 4996) {
										info->peffect = 8421453;
									}
									else if (item == 4840) {
										info->peffect = 8421454;
									}
									else if (item == 5480) {
										info->peffect = 8421456;
									}
									else if (item == 6110) {
										info->peffect = 8421457;
									}
									else if (item == 6308) {
										info->peffect = 8421458;
									}
									else if (item == 6310) {
										info->peffect = 8421459;
									}
									else if (item == 6298) {
										info->peffect = 8421460;
									}
									else if (item == 6756) {
										info->peffect = 8421461;
									}
									else if (item == 7044) {
										info->peffect = 8421462;
									}
									else if (item == 7088) {
										info->peffect = 8421465;
									}
									else if (item == 7098) {
										info->peffect = 8421466;
									}
									else if (item == 7196) {
										info->peffect = 8421471;
									}
									else if (item == 7392) {
										info->peffect = 8421472;
									}
									else if (item == 7488) {
										info->peffect = 8421479;
									}
									else if (item == 7586) {
										info->peffect = 8421480;
									}
									else if (item == 7650) {
										info->peffect = 8421481;
									}
									else if (item == 8036) {
										info->peffect = 8421494;
									}
									else if (item == 8910) {
										info->peffect = 8421505;
									}
									else if (item == 8942) {
										info->peffect = 8421506;
									}
									else if (item == 8948) {
										info->peffect = 8421507;
									}
									else if (item == 8946) {
										info->peffect = 8421509;
									}
									else if (item == 9116 || item == 9118 || item == 9120 || item == 9122) {
										info->peffect = 8421376 + 111;
									}
									else {
										getAutoEffect(peer);
										sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effect);
									}
									break;
								case 6:
									if (((PlayerInfo*)(event.peer->data))->cloth6 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth6 = 0;
										((PlayerInfo*)(event.peer->data))->canDoubleJump = false;
										sendState(peer);
										getAutoEffect(peer);
										sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effect);
										break;
									}
									{
										((PlayerInfo*)(event.peer->data))->cloth6 = pMov->plantingTree;
										if (item == 9006) {
											info->peffect = 8421511;
										}
										else {
											getAutoEffect(peer);
											sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effects);
										}
										((PlayerInfo*)(event.peer->data))->canDoubleJump = true;
										sendState(peer);

										// ^^^^ wings
									}
									break;
								case 7:
									if (pMov->plantingTree == 4288) {
										sendConsoleMsg(peer, "This item is `4disabled!");
										break;
									}
									if (((PlayerInfo*)(event.peer->data))->cloth7 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth7 = 0;
										getAutoEffect(peer);
										sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effect);
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth7 = pMov->plantingTree;
									sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effects);
									break;
								case 8:


									if (((PlayerInfo*)(event.peer->data))->cloth8 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth8 = 0;
										sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effect);
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth8 = pMov->plantingTree;
									sendConsoleMsg(peer, itemDefs.at(pMov->plantingTree).effects);
									break;
								case 9:


								default:
									if (
										def.id == 7166
										|| def.id == 5078 || def.id == 5080 || def.id == 5082 || def.id == 5084
										|| def.id == 5126 || def.id == 5128 || def.id == 5130 || def.id == 5132
										|| def.id == 5144 || def.id == 5146 || def.id == 5148 || def.id == 5150
										|| def.id == 5162 || def.id == 5164 || def.id == 5166 || def.id == 5168
										|| def.id == 5180 || def.id == 5182 || def.id == 5184 || def.id == 5186
										|| def.id == 7168 || def.id == 7170 || def.id == 7172 || def.id == 7174
										|| def.id == 5134 || def.id == 5153 || def.id == 5171 || def.id == 5189
										|| def.id == 9213
										) {
										if (((PlayerInfo*)(event.peer->data))->cloth_ances == pMov->plantingTree) {

											((PlayerInfo*)(event.peer->data))->cloth_ances = 0;
											break;
										}

										((PlayerInfo*)(event.peer->data))->cloth_ances = pMov->plantingTree;

									}
#ifdef TOTAL_LOG
									cout << "[!] Invalid item activated: " << pMov->plantingTree << " by " << ((PlayerInfo*)(event.peer->data))->displayName << endl;
#endif
									break;
								}
								// activate item
								if (info->cloth_hand == 5480) {
									info->peffect = 8421456;
								}

								sendClothes(peer);
								sendState(peer);
								sendPuncheffect(peer);

							END_CLOTHSETTER_FORCE:;
							}
							if (data2->packetType == 18)
							{
								sendPData(peer, pMov);
								// add talk buble
							}
							if (data2->punchX != -1 && data2->punchY != -1) {
								//cout << data2->packetType << endl;
								if (data2->packetType == 3)
								{
									if (((PlayerInfo*)(event.peer->data))->isRotatedLeft = pMov->characterState & 0x10) {
										((PlayerInfo*)(event.peer->data))->RotatedLeft = true;
									}
									else {
										((PlayerInfo*)(event.peer->data))->RotatedLeft = false;
									}
									using namespace std::chrono;
									if (((PlayerInfo*)(peer->data))->lastBREAK + 150 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
									{
										if (data2->plantingTree == 18) {

											if (((PlayerInfo*)(event.peer->data))->cloth_hand == 5480) {
												if (((PlayerInfo*)(event.peer->data))->cloth_face != 4288) {
													if (((PlayerInfo*)(event.peer->data))->isRotatedLeft = pMov->characterState & 0x10) {
														((PlayerInfo*)(event.peer->data))->RotatedLeft = true;
													}
													else {
														((PlayerInfo*)(event.peer->data))->RotatedLeft = false;
													}
													if (data2->punchY == ((PlayerInfo*)(event.peer->data))->y / 32) {
														if (((PlayerInfo*)(event.peer->data))->RotatedLeft == true) {
															sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX - 1, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX - 2, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
											
														}
														else {
															sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX + 1, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX + 2, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
													
														}
													}
													else if (data2->punchX == ((PlayerInfo*)(event.peer->data))->x / 32) {
														if (data2->punchY > ((PlayerInfo*)(event.peer->data))->y / 32) {
															sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX, data2->punchY + 1, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX, data2->punchY + 2, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
											
														}
														else if (data2->punchY < ((PlayerInfo*)(event.peer->data))->y / 32) {
															sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX, data2->punchY - 1, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX, data2->punchY - 2, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
												
														}
														else {
															sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);

														}
													}
													else if (data2->punchY < ((PlayerInfo*)(event.peer->data))->y / 32) {
														if (((PlayerInfo*)(event.peer->data))->RotatedLeft == true) {
															sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX - 1, data2->punchY - 1, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX - 2, data2->punchY - 2, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
													
														}
														else {
															sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX + 1, data2->punchY - 1, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX + 2, data2->punchY - 2, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);

														}
													}
													else if (data2->punchY < ((PlayerInfo*)(event.peer->data))->y / 32) {
														if (((PlayerInfo*)(event.peer->data))->RotatedLeft == true) {
															sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX - 1, data2->punchY - 1, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX - 2, data2->punchY - 2, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
														}
														else {
															sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX + 1, data2->punchY - 1, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX + 2, data2->punchY - 2, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
														}
													}
													else if (data2->punchY > ((PlayerInfo*)(event.peer->data))->y / 32) {
														if (((PlayerInfo*)(event.peer->data))->RotatedLeft == true) {
															sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX - 1, data2->punchY + 1, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX - 2, data2->punchY + 2, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
														}
														else {
															sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX + 1, data2->punchY + 1, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
															sendTileUpdate(data2->punchX + 2, data2->punchY + 2, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
														}

													}


												}
												else if (((PlayerInfo*)(peer->data))->cloth_hand == 5480 || ((PlayerInfo*)(peer->data))->cloth_feet == 1966) {

												}
												else if (((PlayerInfo*)(peer->data))->cloth_hand == 5480 || ((PlayerInfo*)(peer->data))->cloth_feet == 898) {

												}
												else if (((PlayerInfo*)(peer->data))->cloth_hand == 5480 || ((PlayerInfo*)(peer->data))->cloth_feet == 1830) {

												}
											}
											if (((PlayerInfo*)(peer->data))->cloth_hand == 2952) {
												sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
												sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
												sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
												sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);

											}
											else {
												sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
											}
										}
										else {
											sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
										}
									}
								}
								else {

								}
								/*PlayerMoving data;
								//data.packetType = 0x14;
								data.packetType = 0x3;
								//data.characterState = 0x924; // animation
								data.characterState = 0x0; // animation
								data.x = data2->punchX;
								data.y = data2->punchY;
								data.punchX = data2->punchX;
								data.punchY = data2->punchY;
								data.XSpeed = 0;
								data.YSpeed = 0;
								data.netID = ((PlayerInfo*)(event.peer->data))->netID;
								data.plantingTree = data2->plantingTree;
								SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
								cout << "[!] Tile update at: " << data2->punchX << "x" << data2->punchY << endl;*/

							}
							delete data2;
							delete pMov;
						}
						/*char buffer[2048];
						for (int i = 0; i < event->packet->dataLength; i++)
						{
						sprintf(&buffer[2 * i], "%02X", event->packet->data[i]);
						}
						cout << buffer;*/
					}
				}
				break;
				case 5:
					break;
				case 6:
					//cout << GetTextPointerFromPacket(event.packet) << endl;
					break;
				}
				enet_packet_destroy(event.packet);
				break;
			}
			case ENET_EVENT_TYPE_DISCONNECT:
#ifdef TOTAL_LOG
				printf("Peer disconnected.\n");
#endif
				/* Reset the peer's client information. */
				/*ENetPeer* currentPeer;
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;

					GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`w[`2+`w] Player `o" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`o just left the game..."));
					ENetPacket * packet = enet_packet_create(p.data,
						p.len,
						ENET_PACKET_FLAG_RELIABLE);
					enet_peer_send(currentPeer, 0, packet);
					enet_host_flush(server);
				}*/
				int count = 0;
				ENetPeer* currentPeer;
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					count++;
				}
				ofstream myfile;
				myfile.open("onlineplayer.txt");
				myfile << to_string(count);
				myfile.close();
				sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
				((PlayerInfo*)(event.peer->data))->inventory.items.clear();
				delete (PlayerInfo*)event.peer->data;
				event.peer->data = NULL;
			}
		}
	cout << "[!] Program ended??? Huh?" << endl;
	while (1);
	return 0;
}