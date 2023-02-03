#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["Net.AS2.Receiver/Net.AS2.Receiver.csproj", "Net.AS2.Receiver/"]
COPY ["Net.AS2.Core/Net.AS2.Core.csproj", "Net.AS2.Core/"]
COPY ["Net.AS2.Sender/Net.AS2.Sender.csproj", "Net.AS2.Sender/"]
COPY ["Net.AS2.Data/Net.AS2.Data.csproj", "Net.AS2.Data/"]
RUN dotnet restore "Net.AS2.Receiver/Net.AS2.Receiver.csproj"
COPY . .
WORKDIR "/src/Net.AS2.Receiver"
RUN dotnet build "Net.AS2.Receiver.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Net.AS2.Receiver.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Net.AS2.Receiver.dll"]