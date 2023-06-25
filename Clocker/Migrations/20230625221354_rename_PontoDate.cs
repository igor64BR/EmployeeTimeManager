using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Clocker.Migrations
{
    public partial class rename_PontoDate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "Time",
                table: "Ponto",
                newName: "Date");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "Date",
                table: "Ponto",
                newName: "Time");
        }
    }
}
